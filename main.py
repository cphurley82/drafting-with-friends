#!/usr/bin/env python
import logging
import os
import re
import random
import hmac
import json
import time

import webapp2
import jinja2
from lib.bcrypt import bcrypt
from google.appengine.ext import ndb

from lib.mtg import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
all_set_data_file_path = os.path.join(os.path.dirname(__file__), 'm12_only.json')
with open(all_set_data_file_path) as all_sets_file:
    all_sets = json.load(all_sets_file)

#### authentication stuff
secret = 'secret goes here!'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

##### user stuff
def make_pw_hash(name, password):
    hashed = bcrypt.hashpw(name + password, bcrypt.gensalt())
    return hashed

def valid_pw(name, password, hashed):
    return bcrypt.hashpw(name + password, hashed) == hashed

def users_key(group = 'default'):
    return ndb.Key('users', group)

class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()
    friends = ndb.KeyProperty(repeated = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.query(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Draft(ndb.Model):
    name = ndb.StringProperty(required=True)
    coordinator_key = ndb.KeyProperty(required=True)
    user_keys = ndb.KeyProperty(repeated=True)
    drafter_keys = ndb.KeyProperty(repeated=True)
    pack_codes = ndb.StringProperty(repeated=True)
    pack_num = ndb.IntegerProperty(required=True)
    unopened_pack_keys = ndb.KeyProperty(repeated=True)
    in_setup = ndb.BooleanProperty(required=True)
    in_progress = ndb.BooleanProperty(required=True)
    is_done = ndb.BooleanProperty(required=True)
    passing_right = ndb.BooleanProperty(required=True)
    
    created = ndb.DateTimeProperty(auto_now_add=True)
    modified = ndb.DateTimeProperty(auto_now=True)


    num_drafters = ndb.ComputedProperty(lambda self: len(self.drafter_keys))
    num_unopened_packs = ndb.ComputedProperty(
        lambda self: len(self.unopened_pack_keys))

    @classmethod
    def create(cls, coordinator_key, name, pack_codes):
        return Draft(name = name, 
                     user_keys = [coordinator_key],
                     coordinator_key = coordinator_key,
                     pack_codes = pack_codes,
                     pack_num = 0,
                     in_setup = True,
                     in_progress = False,
                     is_done = False,
                     passing_right = False)

    def get_num_picks_queued(self):
        num_picks_queued = 0
        for drafter_key in self.drafter_keys:
            num_picks_queued += drafter_key.get().num_picks_queued
        return num_picks_queued

    def get_current_set_code(self):
        if self.pack_num > 0 and self.pack_num <= len(self.pack_codes):
            return self.pack_codes[self.pack_num-1]

    num_picks_queued = property(fget=get_num_picks_queued)

class Drafter(ndb.Model):
    user_key = ndb.KeyProperty(required = True)
    draft_key = ndb.KeyProperty(required = True)
    position = ndb.IntegerProperty(required = True)

    pack_keys = ndb.KeyProperty(repeated = True)
    picked_cards = ndb.StringProperty(repeated = True)
    
    num_picks_made = ndb.ComputedProperty(lambda self: len(self.picked_cards))
    num_picks_queued = ndb.ComputedProperty(lambda self: len(self.pack_keys))

    @classmethod
    def create(cls, user_key, draft_key, position):
        return Drafter(user_key = user_key,
                       draft_key = draft_key,
                       position = position)

    def get_num_packs_queued(self):
        return len(self.pack_keys)

class Pack(ndb.Model):
    draft_key = ndb.KeyProperty(required=True)
    cards = ndb.StringProperty(repeated=True)

    @classmethod
    def create(cls, draft_key, cards=[]):
        return Pack(draft_key=draft_key, 
                    cards=cards)

class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.integer_id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

class MainPage(MainHandler):
    def get(self):
        setup_drafts = Draft.query(Draft.in_setup == True).fetch()

        setup_ids = []
        for draft in setup_drafts:
            setup_ids.append(draft.key.integer_id())
        logging.error(setup_ids)

        progress_drafts = Draft.query(Draft.in_progress == True).fetch()

        progress_ids = []
        for draft in progress_drafts:
            progress_ids.append(draft.key.integer_id())
        logging.error(progress_ids)

        done_drafts = Draft.query(Draft.is_done == True).fetch()
        done_ids = []
        for draft in done_drafts:
            done_ids.append(draft.key.integer_id())
        logging.error(done_ids)

        self.render('front.html', 
                    setup_ids = setup_ids,
                    progress_ids = progress_ids,
                    done_ids = done_ids)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(MainHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(MainHandler):
    def get(self):
		self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(MainHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class NewDraft(MainHandler):
    def get(self):
        if self.user:
            self.render('new-draft.html', sets = all_sets)
        else:
            self.redirect('/login')

    def post(self):
        name = self.request.get('name')
        pack1 = self.request.get('pack1')
        pack2 = self.request.get('pack2')
        pack3 = self.request.get('pack3')
        draft = Draft.create(coordinator_key=self.user.key, name=name, 
                             pack_codes=[pack1, pack2, pack3])
        draft.put()
        self.redirect('/draft/%s' % str(draft.key.integer_id()))

class DraftPage(MainHandler):
    def lookup_drafter(self, user_key, draft_key):
        drafters_found = Drafter.query(Drafter.user_key == user_key, 
            Drafter.draft_key == draft_key).fetch(1)
        if len(drafters_found) > 0:
            return drafters_found[0]

    def get(self, draft_id):
        draft_key = ndb.Key('Draft', int(draft_id))
        draft = draft_key.get()

        if not draft:
            self.error(404)
            return

        can_join = False
        joined = False
        is_coordinator = False
        status = 'None'
        direction = 'None'
        has_pack = False
        pack = None
        pool = None
        drafter = None
        set_code = None

        if self.user:
            drafter = self.lookup_drafter(user_key=self.user.key, 
                                                  draft_key=draft_key)
        if drafter:
            pool = drafter.picked_cards

        if draft.in_progress:
            status = 'in_progress'
            can_join = False
            set_code = draft.get_current_set_code()
            if draft.passing_right:
                direction = 'Right'
            else:
                direction = 'Left'
            #figure out if the logged in user is also a drafter and give them 
            #their stuff, using a query or something else?
            # logging.error('drafter************************************')
            # logging.error(drafter)
            if drafter:
                if len(drafter.pack_keys) > 0:
                    pack = drafter.pack_keys[0].get()

        elif draft.pack_num == 0:
            status = 'waiting_to_start'
            if self.user:
                can_join = True
                if self.user.key in draft.user_keys:
                    joined = True
                    can_join = False
                if self.user.key == draft.coordinator_key:
                    is_coordinator = True
        else:
            status = 'completed'

        draft_info = {'name':draft.name, 
          'created':draft.created,
          'modified':draft.modified,
          'packs':[],
          'pack_num':draft.pack_num,
          # 'current_pack_code':draft.pack_codes[draft.pack_num],
          'status':status,
          'drafters':[]}

        card_details = {}
        if pack:
            draft_info['pack'] = []
            for card in pack.cards:
                logging.error(card)
                logging.error(set_code)
                
                card_details[card] = mtg.SetUtil().get_card_details(
                    set_code=set_code, card_name=card)
                draft_info['pack'].append(
                    mtg.SetUtil().get_card_details(
                        set_code=set_code, card_name=card))

        for pack_code in draft.pack_codes:
            draft_info['packs'].append(
                {'code':pack_code, 
                 'name':mtg.SetUtil().data()[pack_code]['name']} )

        for drafter_key in draft.drafter_keys:
            draft_info['drafters'].append(
                {'name':drafter_key.get().user_key.get().name, 
                 'num_packs':
                 self.lookup_drafter(drafter_key.get().user_key, 
                    draft_key).get_num_packs_queued()
                 }
                 )

        if drafter:
            draft_info['pool'] = drafter.picked_cards

        # logging.error(draft.drafters)
        self.render('draft.html', 
                    draft_info=draft_info,
                    draft=draft, 
                    set_data=mtg.setutil.data(), 
                    status = status, 
                    direction = direction, 
                    can_join = can_join, 
                    joined = joined, 
                    is_coordinator = is_coordinator, 
                    drafter=drafter,
                    pack=pack,
                    pool=pool,
                    # card_data=mtg.CardUtil().data()
                    card_details=card_details)

    def post(self, draft_id):
        draft_key = ndb.Key('Draft', int(draft_id))
        draft = draft_key.get()

        # logging.error('join_or_leave='+self.request.get('join_or_leave'))
        # logging.error('start='+self.request.get('start'))

        if self.user:
            if self.request.get('join_or_leave') == 'join':
                # logging.error('appending')
                if draft.in_setup:
                    draft.user_keys.append(self.user.key)
                    draft.put()
                else:
                    logging.error('cannot join draft when draft not in_setup')

            if self.request.get('join_or_leave') == 'leave':
                # logging.error('removing')
                if draft.in_setup:
                    draft.user_keys.remove(self.user.key)
                    draft.put()
                else:
                    logging.error('cannot leave draft when draft not in_setup')
            
            if self.request.get('start') == 'start':
                if draft.in_setup:
                    self.start_draft(draft)
                    # time.sleep(1)
                else:
                    logging.error('cannot start draft when draft not in_setup')
            
            if self.request.get('pick'):
                if draft.in_progress:
                    picked_card = self.request.get('pick')
                    self.make_pick(draft=draft, 
                        drafter=self.lookup_drafter(user_key=self.user.key, 
                                                   draft_key=draft_key),
                        picked_card=picked_card)
                    if draft.num_picks_queued == 0:
                        draft_done = not self.next_pack(draft)
                        if draft_done:
                            draft.in_progress = False
                            draft.is_done = True
                            draft.put()
                        
                else:
                    logging.error('cannot make pick when draft not in_progress')

        time.sleep(1)
        self.redirect('/draft/%s' % str(draft.key.integer_id()))

    def start_draft(self, draft):
        draft.in_setup = False
        draft.in_progress = True

        #shuffle user_keys to create random order
        random.shuffle(draft.user_keys)

        #create the individual drafter items
        position = 0
        drafter_entities = []
        for user_key in draft.user_keys:
            drafter_entities.append(Drafter.create(user_key=user_key, 
                draft_key=draft.key, position=position))
            position += 1
        draft.drafter_keys = ndb.put_multi(drafter_entities)
        logging.error('424: draft')
        logging.error(draft)

        pack_entities = []
        #get boosters for all the packs
        for pack_code in draft.pack_codes:
            packs = mtg.setutil.generate_boosters(
                num=draft.num_drafters, 
                set_code=pack_code)
            random.shuffle(packs)
            for pack in packs:
                pack_entities.append(Pack.create(draft_key=draft.key, 
                                                 cards=pack))
        draft.unopened_pack_keys = ndb.put_multi(pack_entities)
        draft.put()
        time.sleep(5)
        logging.error('440: draft')
        logging.error(draft)
        self.next_pack(draft)
                
    #returns True if there is another pack to go to, False if not
    def next_pack(self, draft):
        #if there are enough unopened packs
        if draft.num_unopened_packs >= draft.num_drafters:
            draft.pack_num += 1
            draft.passing_right = not draft.passing_right

            # time.sleep(5) #wait before getting the drafter keys due to eventual consistency problems
            # logging.error('448: draft')
            # logging.error(draft)
            # logging.error('454: draft.drafter_keys')
            # logging.error(draft.drafter_keys)
            drafter_keys = list(draft.drafter_keys) #make a copy because ndb does something wierd and converts the key to _BaseValue sometimes
            # logging.error('457: drafter_keys')
            # logging.error(drafter_keys)
            for drafter_key in drafter_keys:
                # logging.error('451: drafter_key=')
                # logging.error(drafter_key)
                drafter = drafter_key.get()
                
                #give drafter a pack and remove it from the unopened pack list
                new_pack = draft.unopened_pack_keys[0]
                drafter.pack_keys.append(new_pack)
                draft.unopened_pack_keys.remove(new_pack)

                logging.error('drafter.pack_keys[0].get()=')
                logging.error(drafter.pack_keys[0].get())

                drafter.put()
                draft.put()
                time.sleep(1)
            return True

        return False

    def make_pick(self, draft, drafter, picked_card):
        if len(drafter.pack_keys) > 0:
            pack_key = drafter.pack_keys[0]
            pack = pack_key.get()
            if picked_card in pack.cards:
                #drafter puts the card in pool
                pack.cards.remove(picked_card)
                drafter.picked_cards.append(picked_card)

                #drafter passes the pack to the next player if there are cards 
                #left to pass, otherwise pack just gets removed
                drafter.pack_keys.remove(pack_key)
                if len(pack.cards) > 0:
                    recieving_drafter = None                   
                    if draft.passing_right:
                        recieving_position = drafter.position + 1
                        if recieving_position >= draft.num_drafters:
                            recieving_position = 0
                    else:
                        recieving_position = drafter.position - 1
                        if recieving_position < 0:
                            recieving_position = draft.num_drafters - 1
                    recieving_drafter = draft.drafter_keys[recieving_position].get()
                    recieving_drafter.pack_keys.append(pack_key)
                    recieving_drafter.put()

                pack.put()
                drafter.put()
                draft.put()
                return True #since we have successfully picked a card
            else:
                logging.error('picked card is not in current pack')
        else:
            logging.error('no pack to pick from')
        return False #since we did not successfully pick a card

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/newdraft', NewDraft),
    ('/draft/([0-9]+)?', DraftPage),
    ], 
    debug=True)
