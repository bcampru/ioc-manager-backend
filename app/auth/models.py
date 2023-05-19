from app import db


class Users(db.Model):
    id = db.Column('user_id', db.Integer, primary_key=True)
    email = db.Column(db.String(24))
    password = db.Column(db.String(64))
    name = db.Column(db.String(24))
    surname = db.Column(db.String(24))

    def save(self):
        db.session.add(self)
        db.session.commit()

    def __init__(self, email, password, name, surname):
        self.email = email
        self.password = password
        self.name = name
        self.surname = surname

    def __repr__(self):
        return "<User: email - {}; Password - {}; Name - {}; Surname - {};>".format(self.email, self.password, self.name, self.surname)


class InvalidToken(db.Model):
    __tablename__ = "invalid_tokens"
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String)

    def save(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_invalid(cls, jti):
        """ Determine whether the jti key is on the blocklist return bool"""
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)
