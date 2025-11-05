import json
import os
import random
from datetime import datetime
from typing import List, Optional

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import relationship, scoped_session, sessionmaker, declarative_base
from passlib.hash import bcrypt

from lib.mtg.setutil import SetUtil

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///drafting_with_friends.db")
SECRET_KEY = os.environ.get("DWF_SECRET_KEY", "dev-secret-change-me")

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))
Base = declarative_base()
set_util = SetUtil()


def json_list(value: str) -> list:
    if not value:
        return []
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return []


def dumps_list(values: list) -> str:
    return json.dumps(list(values))


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    pw_hash = Column(String(255), nullable=False)
    email = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    drafters = relationship("Drafter", back_populates="user", cascade="all, delete-orphan")

    def verify_password(self, password: str) -> bool:
        return bcrypt.verify(self.name + password, self.pw_hash)


class Draft(Base):
    __tablename__ = "drafts"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    coordinator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    pack_codes = Column(Text, nullable=False, default="[]")
    participant_ids = Column(Text, nullable=False, default="[]")
    pick_size = Column(Integer, nullable=False, default=1)

    pack_num = Column(Integer, nullable=False, default=0)
    in_setup = Column(Boolean, nullable=False, default=True)
    in_progress = Column(Boolean, nullable=False, default=False)
    is_done = Column(Boolean, nullable=False, default=False)
    passing_right = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    coordinator = relationship("User")
    drafters = relationship("Drafter", back_populates="draft", cascade="all, delete-orphan")
    packs = relationship("Pack", back_populates="draft", cascade="all, delete-orphan")

    @property
    def pack_codes_list(self) -> list:
        return json_list(self.pack_codes)

    def set_pack_codes(self, codes: list) -> None:
        self.pack_codes = dumps_list(codes)

    @property
    def participant_ids_list(self) -> list:
        return json_list(self.participant_ids)

    def add_participant(self, user_id: int) -> None:
        participants = set(self.participant_ids_list)
        participants.add(int(user_id))
        self.participant_ids = dumps_list(sorted(participants))

    def remove_participant(self, user_id: int) -> None:
        participants = [pid for pid in self.participant_ids_list if pid != int(user_id)]
        self.participant_ids = dumps_list(participants)

    def current_set_code(self) -> Optional[str]:
        codes = self.pack_codes_list
        if 0 < self.pack_num <= len(codes):
            return codes[self.pack_num - 1]
        return None

    def queued_pack_count(self, db_session) -> int:
        return (
            db_session.query(Pack)
            .filter(Pack.draft_id == self.id, Pack.holder_id.is_not(None))
            .count()
        )

    def unopened_pack_count(self, db_session) -> int:
        return (
            db_session.query(Pack)
            .filter(Pack.draft_id == self.id, Pack.holder_id.is_(None), Pack.round_number > self.pack_num)
            .count()
        )


class Drafter(Base):
    __tablename__ = "drafters"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    draft_id = Column(Integer, ForeignKey("drafts.id"), nullable=False)
    position = Column(Integer, nullable=False)
    picked_cards = Column(Text, nullable=False, default="[]")

    user = relationship("User", back_populates="drafters")
    draft = relationship("Draft", back_populates="drafters")
    packs = relationship("Pack", back_populates="holder", cascade="all, delete-orphan")

    @property
    def picks(self) -> list:
        return json_list(self.picked_cards)

    def add_picks(self, cards: list) -> None:
        updated = self.picks
        updated.extend(cards)
        self.picked_cards = dumps_list(updated)

    def clear_pack(self, pack: "Pack") -> None:
        if pack in self.packs:
            self.packs.remove(pack)

    def sorted_packs(self) -> list:
        return sorted(self.packs, key=lambda pack: (pack.round_number, pack.id))


class Pack(Base):
    __tablename__ = "packs"

    id = Column(Integer, primary_key=True)
    draft_id = Column(Integer, ForeignKey("drafts.id"), nullable=False)
    round_number = Column(Integer, nullable=False)
    position = Column(Integer, nullable=False)
    cards = Column(Text, nullable=False, default="[]")
    holder_id = Column(Integer, ForeignKey("drafters.id"))

    draft = relationship("Draft", back_populates="packs")
    holder = relationship("Drafter", back_populates="packs")

    @property
    def card_list(self) -> list:
        return json_list(self.cards)

    def set_cards(self, cards: list) -> None:
        self.cards = dumps_list(cards)


Base.metadata.create_all(engine)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY

    @app.before_request
    def create_session():
        g.db = SessionLocal()
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            g.user = g.db.get(User, user_id)

    @app.teardown_request
    def remove_session(exception=None):
        SessionLocal.remove()

    @app.context_processor
    def inject_globals():
        return {"user": g.get("user")}

    def render_draft(draft: Draft, drafter: Optional[Drafter]):
        set_data = set_util.data()
        draft_info = {
            "id": draft.id,
            "name": draft.name,
            "created": draft.created_at.strftime("%b %d, %Y"),
            "modified": draft.updated_at.strftime("%b %d, %Y"),
            "pack_num": draft.pack_num,
            "status": "completed" if draft.is_done else ("in_progress" if draft.in_progress else "waiting_to_start"),
            "passing_right": draft.passing_right,
            "pick_size": draft.pick_size,
            "packs": [],
            "users": [],
            "drafters": [],
            "direction": "Right" if draft.passing_right else "Left",
        }

        for code in draft.pack_codes_list:
            details = set_data.get(code, {"name": code})
            draft_info["packs"].append({"code": code, "name": details.get("name", code)})

        for participant_id in draft.participant_ids_list:
            participant = g.db.get(User, participant_id)
            if participant:
                draft_info["users"].append(participant.name)

        drafter_rows = (
            g.db.query(Drafter)
            .filter(Drafter.draft_id == draft.id)
            .order_by(Drafter.position.asc())
            .all()
        )
        for row in drafter_rows:
            draft_info["drafters"].append({
                "name": row.user.name,
                "num_packs": len(row.sorted_packs()),
            })

        if drafter:
            draft_info["pool"] = drafter.picks
        else:
            draft_info["pool"] = []

        current_pack = None
        if drafter:
            packs = drafter.sorted_packs()
            if packs:
                current_pack = packs[0]

        draft_info["pack"] = []
        if current_pack:
            set_code = draft.current_set_code()
            for card_name in current_pack.card_list:
                card_details = set_util.get_card_details(set_code, card_name)
                draft_info["pack"].append(card_details)

        return draft_info

    def start_draft(draft: Draft):
        participants = draft.participant_ids_list
        random.shuffle(participants)

        drafter_rows = []
        for index, user_id in enumerate(participants):
            drafter_rows.append(Drafter(user_id=user_id, draft_id=draft.id, position=index))
        g.db.add_all(drafter_rows)
        g.db.flush()

        draft.drafters = drafter_rows
        draft.in_setup = False
        draft.in_progress = True
        draft.is_done = False
        draft.pack_num = 0
        draft.passing_right = True

        for round_number, set_code in enumerate(draft.pack_codes_list, start=1):
            boosters = set_util.generate_boosters(len(drafter_rows), set_code)
            random.shuffle(boosters)
            for position, cards in enumerate(boosters):
                pack = Pack(draft_id=draft.id, round_number=round_number, position=position)
                pack.set_cards(cards)
                g.db.add(pack)

        g.db.flush()
        next_pack(draft)

    def next_pack(draft: Draft) -> bool:
        next_round = draft.pack_num + 1
        unopened = (
            g.db.query(Pack)
            .filter(
                Pack.draft_id == draft.id,
                Pack.round_number == next_round,
                Pack.holder_id.is_(None),
            )
            .order_by(Pack.position.asc())
            .all()
        )
        if len(unopened) < len(draft.drafters):
            return False

        draft.pack_num = next_round
        draft.passing_right = not draft.passing_right

        ordered_drafters = (
            g.db.query(Drafter)
            .filter(Drafter.draft_id == draft.id)
            .order_by(Drafter.position.asc())
            .all()
        )
        for drafter, pack in zip(ordered_drafters, unopened):
            pack.holder = drafter
            g.db.add(pack)
        g.db.add(draft)
        g.db.flush()
        return True

    def advance_pack_if_ready(draft: Draft):
        if draft.queued_pack_count(g.db) == 0:
            has_more = next_pack(draft)
            if not has_more:
                draft.in_progress = False
                draft.is_done = True
            g.db.add(draft)

    def make_pick(draft: Draft, drafter: Drafter, selected_cards: List[str]):
        packs = drafter.sorted_packs()
        if not packs:
            flash("You do not have a pack to pick from.", "error")
            return

        pack = packs[0]
        cards = pack.card_list
        missing = [card for card in selected_cards if card not in cards]
        if missing:
            flash("One or more selected cards are no longer in the pack.", "error")
            return

        for card in selected_cards:
            cards.remove(card)
        pack.set_cards(cards)
        drafter.add_picks(selected_cards)

        pack.holder = None
        drafter.clear_pack(pack)

        if cards:
            ordered_drafters = (
                g.db.query(Drafter)
                .filter(Drafter.draft_id == draft.id)
                .order_by(Drafter.position.asc())
                .all()
            )
            total = len(ordered_drafters)
            if draft.passing_right:
                next_position = (drafter.position + 1) % total
            else:
                next_position = (drafter.position - 1) % total
            receiver = ordered_drafters[next_position]
            pack.holder = receiver
            g.db.add(receiver)

        g.db.add_all([pack, drafter, draft])
        g.db.flush()
        advance_pack_if_ready(draft)

    def lookup_drafter(draft: Draft, user: Optional[User]) -> Optional[Drafter]:
        if not user:
            return None
        return (
            g.db.query(Drafter)
            .filter(Drafter.draft_id == draft.id, Drafter.user_id == user.id)
            .one_or_none()
        )

    @app.route("/")
    def index():
        setup = (
            g.db.query(Draft)
            .filter(Draft.in_setup.is_(True))
            .order_by(Draft.created_at.desc())
            .all()
        )
        progress = (
            g.db.query(Draft)
            .filter(Draft.in_progress.is_(True))
            .order_by(Draft.updated_at.desc())
            .all()
        )
        completed = (
            g.db.query(Draft)
            .filter(Draft.is_done.is_(True))
            .order_by(Draft.updated_at.desc())
            .all()
        )
        return render_template(
            "front.html",
            setup_drafts=setup,
            progress_drafts=progress,
            done_drafts=completed,
        )

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            verify = request.form.get("verify", "")
            email = request.form.get("email", "").strip() or None

            errors = {}
            if not (3 <= len(username) <= 20) or not all(ch.isalnum() or ch in "_-" for ch in username):
                errors["error_username"] = "That's not a valid username."
            if not (3 <= len(password) <= 20):
                errors["error_password"] = "That wasn't a valid password."
            elif password != verify:
                errors["error_verify"] = "Your passwords didn't match."
            if email and ("@" not in email or "." not in email):
                errors["error_email"] = "That's not a valid email."

            if g.db.query(User).filter(User.name == username).first():
                errors["error_username"] = "That user already exists."

            if errors:
                return render_template("signup-form.html", **errors, username=username, email=email)

            pw_hash = bcrypt.hash(username + password)
            user = User(name=username, pw_hash=pw_hash, email=email)
            g.db.add(user)
            g.db.commit()
            session["user_id"] = user.id
            return redirect(url_for("index"))

        return render_template("signup-form.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        username = ""
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = g.db.query(User).filter(User.name == username).one_or_none()
            if user and user.verify_password(password):
                session["user_id"] = user.id
                return redirect(url_for("index"))
            flash("Invalid login", "error")
        return render_template("login-form.html", username=username)

    @app.route("/logout")
    def logout():
        session.pop("user_id", None)
        return redirect(url_for("index"))

    @app.route("/newdraft", methods=["GET", "POST"])
    def newdraft():
        if not g.user:
            return redirect(url_for("login"))

        sets = set_util.data()
        default_code = next(iter(sets.keys())) if sets else ""
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            pack_codes = [
                request.form.get("pack1", default_code),
                request.form.get("pack2", default_code),
                request.form.get("pack3", default_code),
            ]
            pick_size = int(request.form.get("pick_size", "1"))

            if not name:
                flash("Draft name is required.", "error")
                return render_template(
                    "new-draft.html",
                    sets=sets,
                    name=name,
                    pack1=pack_codes[0],
                    pack2=pack_codes[1],
                    pack3=pack_codes[2],
                    pick_size=pick_size,
                )

            if any(code not in sets for code in pack_codes):
                flash("Please choose valid packs.", "error")
                return render_template(
                    "new-draft.html",
                    sets=sets,
                    name=name,
                    pack1=pack_codes[0],
                    pack2=pack_codes[1],
                    pack3=pack_codes[2],
                    pick_size=pick_size,
                )

            draft = Draft(name=name, coordinator_id=g.user.id, pick_size=pick_size)
            draft.set_pack_codes(pack_codes)
            draft.add_participant(g.user.id)
            g.db.add(draft)
            g.db.commit()
            return redirect(url_for("draft_page", draft_id=draft.id))

        return render_template(
            "new-draft.html",
            sets=sets,
            pick_size=1,
            pack1=default_code,
            pack2=default_code,
            pack3=default_code,
        )

    @app.route("/draft/<int:draft_id>", methods=["GET", "POST"])
    @app.route("/draft/<int:draft_id>.json", methods=["GET", "POST"])
    def draft_page(draft_id: int):
        draft = g.db.get(Draft, draft_id)
        if not draft:
            abort(404)

        wants_json = request.path.endswith(".json")
        drafter = lookup_drafter(draft, g.user)

        if request.method == "POST":
            if "join_or_leave" in request.form and g.user:
                action = request.form.get("join_or_leave")
                if action == "join" and draft.in_setup and g.user.id not in draft.participant_ids_list:
                    draft.add_participant(g.user.id)
                    g.db.add(draft)
                    g.db.commit()
                elif action == "leave" and draft.in_setup and g.user.id in draft.participant_ids_list:
                    draft.remove_participant(g.user.id)
                    g.db.add(draft)
                    g.db.commit()
            elif request.form.get("start") == "start" and g.user and g.user.id == draft.coordinator_id:
                if draft.in_setup and len(draft.participant_ids_list) > 1:
                    start_draft(draft)
                    g.db.commit()
                else:
                    flash("You need at least two participants to start a draft.", "error")
            elif "pick" in request.form and draft.in_progress and drafter:
                selected_cards = request.form.getlist("pick")
                if len(selected_cards) != draft.pick_size:
                    flash(f"You must select exactly {draft.pick_size} cards.", "error")
                else:
                    make_pick(draft, drafter, selected_cards)
                    g.db.commit()
            return redirect(url_for("draft_page", draft_id=draft.id))

        draft_info = render_draft(draft, drafter)
        draft_info["can_join"] = bool(g.user and draft.in_setup and g.user.id not in draft.participant_ids_list)
        draft_info["joined"] = bool(g.user and g.user.id in draft.participant_ids_list)
        draft_info["is_coordinator"] = bool(g.user and g.user.id == draft.coordinator_id)

        if wants_json:
            return jsonify(draft_info)

        return render_template("draft.html", draft_info=draft_info)

    return app


app = create_app()

