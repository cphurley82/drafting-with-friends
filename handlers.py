'''
Created on Nov 17, 2015

@author: cphurley
'''
import logging
import os
import re
import random
import json
import time
import webapp2
import jinja2

from google.appengine.ext import ndb

from lib.mtg.setutil import SetUtil
from lib.db.user import User
from lib.db.draft import Draft
from lib.db.drafter import Drafter
from lib.db.pack import Pack
from lib.utils import make_secure_val, check_secure_val

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

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
#         logging.error(setup_ids)

        progress_drafts = Draft.query(Draft.in_progress == True).fetch()

        progress_ids = []
        for draft in progress_drafts:
            progress_ids.append(draft.key.integer_id())
#         logging.error(progress_ids)

        done_drafts = Draft.query(Draft.is_done == True).fetch()
        done_ids = []
        for draft in done_drafts:
            done_ids.append(draft.key.integer_id())
#         logging.error(done_ids)

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
            self.render('new-draft.html', sets = SetUtil().data())
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
#         has_pack = False
        pack = None
#         pool = None
        drafter = None
        set_code = None

        if self.user:
            drafter = self.lookup_drafter(user_key=self.user.key, 
                                                  draft_key=draft_key)
#         if drafter:
#             pool = drafter.picked_cards

        if draft.in_progress:
            status = 'in_progress'
#             can_join = False
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

        time_fmt = '%b %d, %Y'
        draft_info = {'name':draft.name, 
          'created':draft.created.strftime(time_fmt),
          'modified':draft.modified.strftime(time_fmt),
          'packs':[],
          'pack_num':draft.pack_num,
          # 'current_pack_code':draft.pack_codes[draft.pack_num],
          'status':status,
          'users':[],
          'drafters':[],
          'can_join':can_join,
          'joined':joined,
          'is_coordinator':is_coordinator,
          }
        
        if direction:
            draft_info['direction'] = direction

        card_details = {}
        if pack:
            draft_info['pack'] = []
            for card in pack.cards:
#                 logging.error(card)
#                 logging.error(set_code)
                
                card_details[card] = SetUtil().get_card_details(
                    set_code=set_code, card_name=card)
                draft_info['pack'].append(
                    SetUtil().get_card_details(
                        set_code=set_code, card_name=card))
            if len(pack.cards) < 1:
                #this should never happen but there seems to be a bug so
                # I'm deleting the empty pack TODO: create a better way to 
                # fix this.
                logging.error("pack should have at least one card but is empty")
                logging.error("removing pack_key:")
                logging.error(pack)
                logging.error("from drafter:")
                logging.error(drafter)
                drafter.pack_keys.remove(pack)

        for pack_code in draft.pack_codes:
            draft_info['packs'].append(
                {'code':pack_code, 
                 'name':SetUtil().data()[pack_code]['name']} )

        for drafter_key in draft.drafter_keys:
            draft_info['drafters'].append(
                {'name':drafter_key.get().user_key.get().name, 
                 'num_packs':
                 self.lookup_drafter(drafter_key.get().user_key, 
                    draft_key).get_num_packs_queued()
                 }
                 )
            
        for user_key in draft.user_keys:
            draft_info['users'].append(user_key.get().name)

        if drafter:
            draft_info['pool'] = drafter.picked_cards

        # logging.error(draft.drafters)
        if self.format is 'json':
            self.render_json(draft_info)
        else:
            self.render('draft.html', draft_info=draft_info)

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

#         time.sleep(1)
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
#         logging.error('424: draft')
#         logging.error(draft)

        pack_entities = []
        #get boosters for all the packs
        for pack_code in draft.pack_codes:
            packs = SetUtil().generate_boosters(
                num=draft.num_drafters, 
                set_code=pack_code)
            random.shuffle(packs)
            for pack in packs:
                pack_entities.append(Pack.create(draft_key=draft.key, 
                                                 cards=pack))
        draft.unopened_pack_keys = ndb.put_multi(pack_entities)
        draft.put()
#         time.sleep(5)
#         logging.error('440: draft')
#         logging.error(draft)
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

#                 logging.error('drafter.pack_keys[0].get()=')
#                 logging.error(drafter.pack_keys[0].get())

                drafter.put()
                draft.put()
#                 time.sleep(1)
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
