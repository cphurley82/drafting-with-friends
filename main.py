#!/usr/bin/env python
import webapp2

from handlers import MainPage, Signup, Login, Logout, NewDraft, DraftPage

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/newdraft', NewDraft),
    ('/draft/([0-9]+)(?:\.json)?', DraftPage),
    ], 
    debug=True)
