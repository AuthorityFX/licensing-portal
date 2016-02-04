# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2012-2016, Ryan P. Wilson
#
#     Authority FX, Inc.
#     www.authorityfx.com

import tw2.core as twc
import tw2.forms as twf
import tw2.dynforms as twd
from tg import flash, url
import genshi

class MatchPassword(twc.MatchValidator):

    msgs = {
        'mismatch_param': "Passwords must match"
    }

    def __init__(self, other_field, **kw):
        super(twc.MatchValidator, self).__init__(**kw)
        self.other_field = other_field

    def validate_python(self, value, state):

        if self.other_field in state:
            if value != state[self.other_field]:
                raise twc.ValidationError('mismatch_param', self)

class MatchEmail(MatchPassword):

    msgs = {
        'mismatch_param': "Emails must match"
    }

class SettingsForm(twf.Form):

    submit = twf.SubmitButton(value='Update')
    action = '/update_settings'

    class child(twf.TableLayout):

        hover_help = True

        name = twf.TextField(help_text='Enter a new display name.')
        login_email = twf.TextField(help_text='Enter a new login email.', validator=twc.EmailValidator)
        confirm_email = twf.TextField(help_text='Confirm new login email address.', validator=MatchEmail('new_login_email'))
        new_password = twf.PasswordField(help_text='Enter new password.')
        confirm_password = twf.PasswordField(help_text='Confirm new password.', validator=MatchPassword('new_password'))
        current_password = twf.PasswordField(help_text='Enter current password.', validator=twc.Required)

licnese_grid = twf.DataGrid(fields=[
    ('Plugin', 'Plugin.display_name'),
    ('Type', 'LicenseType.display_name'),
    ('Count', 'License.count'),
    ('Available', 'License.available')
])

def redeemLicense(obj):
    if obj.Assignemt.count_1  > 0:
        return genshi.Markup('<a href="%s">Redeem</a>' % url('/create_license', params=dict(id=obj.Computer.id)))
    else:
        return ''

computer_grid = twf.DataGrid(fields=[
    ('Name', 'Computer.display_name'),
    ('MAC Address', 'Computer.uuid1'),
    ('License', lambda obj: redeemLicense(obj))
    #('License', lambda obj: genshi.Markup('<a href="%s">Redeem</a>' % url('/create_license', params=dict(id=obj.id))))
])

assignment_grid = twf.DataGrid(fields=[
    ('Count', 'count'),
    #('License', lambda obj:genshi.Markup('<a href="%s">Redeem</a>' % url('/settings', params=dict(item_id=obj.id))))
])

class ManageForm(twf.Form):
    title = 'Manage'
    class child(twf.TableLayout):

        hover_help = True

        class Assignments(twd.GrowingGridLayout):
            computer = twf.SingleSelectField(options='display_name', validator=twc.Required)
            phone_number = twf.TextField()
            personal = twf.CheckBox()


        name = twf.TextField(help_text='Enter a new display name.')


