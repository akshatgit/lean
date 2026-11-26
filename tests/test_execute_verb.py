"""Execution checks apply to the row that survives a load and reaches a runner."""
from textwrap import dedent

import pytest

from keyhole import air
from keyhole.adapters import FastAPISQLAlchemyAdapter
from keyhole.checker import check_endpoints
from keyhole.policy import load_policy


@pytest.mark.parametrize(("check", "verdict"), [
    ("if job is not None and job.owner_id != caller.id: job = None", "safe"),
    ("", "possible_violation"),
    ("if enabled and job.owner_id != caller.id: job = None", "possible_violation"),
    ("if job.owner_id != job_id: job = None", "possible_violation"),
])
def test_execute_loaded_job(tmp_path, check, verdict):
    (tmp_path / "app.py").write_text(dedent(f"""\
        from fastapi import Depends, FastAPI, HTTPException
        from sqlmodel import Field, Session, SQLModel
        from external import current_user, get_db, scheduler
        app = FastAPI()

        class Job(SQLModel, table=True):
            id: int = Field(primary_key=True)
            owner_id: int

        def run_job(job):
            return job.id

        @app.post("/jobs/{{job_id}}")
        def dispatch(job_id: int, enabled: bool, caller=Depends(current_user), session: Session=Depends(get_db)):
            scheduler.ensure_available()
            job = session.get(Job, job_id)
            {check}
            if job is None:
                raise HTTPException(404)
            return run_job(job)
    """))
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(dedent("""\
        principal:
          id: caller.id
          dependencies: [current_user]
        resources:
          Job:
            confirmed: true
            execute: owner(owner_id)
    """))
    policy = load_policy(policy_path)
    endpoints = FastAPISQLAlchemyAdapter().extract(tmp_path, {}, policy=policy)
    result, = check_endpoints(endpoints, policy)
    execution, = [e for e in result.effects if e.effect.kind == "execute"]
    assert execution.effect.resource == "Job"
    if verdict == "safe" or not check:
        assert execution.effect.selector == air.eq(air.fld("id"), air.param("job_id"))
    assert execution.verdict == verdict
    owner = air.eq(air.fld("owner_id"), air.principal("id"))
    assert (owner in execution.effect.guards) == (verdict == "safe")
    assert all(owner not in e.effect.guards for e in result.effects if e.effect.kind == "read")
    assert any("scheduler.ensure_available" in o.call for o in result.endpoint.opaque)


def test_detached_runner_input_keeps_the_unchecked_lookup_alternative(tmp_path):
    (tmp_path / "app.py").write_text(dedent("""\
        from fastapi import Depends, FastAPI, HTTPException
        from sqlmodel import Field, SQLModel, select
        from external import current_user, get_db, run_job_by_name
        app = FastAPI()

        class Job(SQLModel, table=True):
            id: int = Field(primary_key=True)
            owner_id: int

        class JobView(SQLModel):
            id: int

        def lookup(session, key, user):
            try:
                item = session.get(Job, int(key))
            except ValueError:
                item = session.exec(select(Job).where(Job.owner_id == user.id)).first()
            if item is None:
                raise HTTPException(404)
            return JobView.model_validate(item, from_attributes=True)

        @app.post("/dispatch/{key}")
        def dispatch(key: str, caller=Depends(current_user), session=Depends(get_db)):
            try:
                task = lookup(session, key, caller)
            except HTTPException:
                task = None
            if task is None:
                return
            return run_job_by_name(job=task)
    """))
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("principal: {id: caller.id, dependencies: [current_user]}\n"
                           "resources: {Job: {confirmed: true, execute: owner(owner_id)}}\n")
    policy = load_policy(policy_path)
    endpoints = FastAPISQLAlchemyAdapter().extract(tmp_path, {}, policy=policy)
    result, = check_endpoints(endpoints, policy)
    execution, = [e for e in result.effects if e.effect.kind == "execute"]
    assert execution.verdict == "possible_violation"
    assert execution.effect.resource == "Job"
    assert execution.effect.selector is True
    assert execution.effect.guards == []
