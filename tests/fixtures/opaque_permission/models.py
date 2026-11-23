from sqlalchemy import Column, Integer


class Document:
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)


class User:
    pass
