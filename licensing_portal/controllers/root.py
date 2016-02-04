# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2012-2016, Ryan P. Wilson
#
#     Authority FX, Inc.
#     www.authorityfx.com

# -*- coding: utf-8 -*-
"""Main Controller"""

from tg import expose, flash, require, url, lurl, request, redirect, tmpl_context, validate, response
from tg.i18n import ugettext as _, lazy_ugettext as l_
from tg import predicates, require
from licensing_portal import model
from licensing_portal.controllers.secure import SecureController
from licensing_portal.model import DBSession, metadata
from tgext.admin.tgadminconfig import TGAdminConfig
from tgext.admin.controller import AdminController

from licensing_portal.lib.base import BaseController
from licensing_portal.controllers.error import ErrorController

import tw2.core as twc
import tw2.forms as twf
import tw2.dynforms as twd
import genshi
import re

from sqlalchemy import func

import StringIO
import pylons

import socket
import sys

import random
import string
import smtplib

__all__ = ['RootController']

#Email server
class SendMail:

    def __init__(self):
        try:
            self._server = smtplib.SMTP("smtp.gmail.com", 587)
            self._server.ehlo()
            self._server.starttls()
            self._server.ehlo()
            self._server.login("username", "password")
        except Exception, e:
            raise Exception("Could connect to pop server - " + str(e))

    def send_mail(self, receipient, subject, message, BCC=None):

        sender = "licensing@authorityfx.com"

        body = string.join((
        "From: %s" % sender,
        "To: %s" % receipient,
        "Subject: %s" % subject,
        "", message
        ), "\r\n")

        try:
            if BCC!=None:
                toaddrs = [receipient] + [BCC]
            else:
                toaddrs = [receipient]
            self._server.sendmail(sender, toaddrs, body)
        except Exception, e:
            raise Exception("Could not send email - " + str(e))


#Forms and form validators
#_________________________________________________________

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

class MacValidator(twc.RegexValidator):

    msgs = {
        'badregex': ('bademail', _('Must be a valid MAC address.  12 character alphanumeric. No special characters')),
    }
    regex = re.compile('^[a-zA-Z0-9]{12}$')

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

license_grid = twf.DataGrid(fields=[
    ('id', 'License.id'),
    ('Plugin', 'Plugin.display_name'),
    ('Type', 'LicenseType.display_name'),
    ('Floating', 'License.floating'),
    ('Count', 'License.count'),
    ('Available', 'License.available')

])

def createLicenseList(obj):
    licenses = DBSession.query(func.sum(model.Assignment.count).label('count_sum'), model.Assignment, model.Plugin, model.License, model.LicenseType).join(model.License).join(model.Plugin).join(model.LicenseType).filter(model.Assignment.computer_id==obj.id, model.Assignment.user_id==obj.user_id).group_by(model.License.id).all()

    if len(licenses) > 0:
        license_list = '(' + str(len(licenses)) + ') license' + ('s' if len(licenses) > 1 else '') + ': '
    else:
        license_list = 'No licenses assigned'
    for license in licenses:
        floating = ''
        if license.License.floating == True:
            floating = ':floating'
        license_list += license.Plugin.display_name + ":" + license.LicenseType.display_name + floating + ":" + str(license.count_sum) +  ", "

    return license_list.strip().strip(',')

def redeemLicense(obj):
    count = DBSession.query(model.Assignment).filter(model.Assignment.computer_id==obj.id, model.Assignment.user_id==obj.user_id).count()
    if count  > 0:
        return  genshi.Markup('<form method="POST" action="%s" class="button-to"><input type="hidden" name="_method" value="DELETE" /><input class="delete-button" onclick="return confirm(\'All assignments to this computer will be locked.  Are you sure you want to redeem the assigned licenses?\');" value="Redeem" type="submit" style="background-color:transparent; float:left; border:0; color: #286571; display:inline; margin:0; padding:0;"/></form>' % url('/create_license', params=dict(id=obj.id)))
    else:
        return genshi.Markup('<a href="%s">Delete </a>' % url('/delete_computer', params=dict(id=obj.id)))

computer_grid = twf.DataGrid(fields=[
    ('id', 'id'),
    ('Name', 'display_name'),
    ('MAC Address', 'uuid1'),
    ('Assignments', createLicenseList),
    ('Action', redeemLicense)
])

def removeAssignment(obj):
    locked = DBSession.query(model.Assignment.locked).filter(model.Assignment.id==obj.Assignment.id, model.Assignment.user_id==obj.Assignment.user_id).first().locked
    if locked == True:
        return ''
    else:
        return genshi.Markup('<a href="%s">Delete</a>' % url('/delete_assignment', params=dict(id=obj.Assignment.id)))


assignment_grid = twf.DataGrid(fields=[
    ('id', 'Assignment.id'),
    ('Computer', 'Computer.display_name'),
    ('Plugin', 'Plugin.display_name'),
    ('Computer id', 'Computer.id'),
    ('License id', 'Assignment.license_id'),
    ('Count', 'Assignment.count'),
    ('Action', removeAssignment)
])

class AddComputerForm(twf.Form):

    submit = twf.SubmitButton(value='Add Computer')
    action = '/add_computer'
    show_errors = True

    class child(twf.TableLayout):

        hover_help = True

        name = twf.TextField(help_text='Enter a computer name.', validator=twc.Required)
        mac = twf.TextField(help_text='Enter a mac address. 12 character alphanumeric.', validator=MacValidator(required=True))

def get_computers(user_id):
    return DBSession.query(model.Computer).filter(model.Computer.user_id==user_id).all()

def get_licenses(user_id):
    return DBSession.query(model.License, model.Plugin, model.LicenseType).join(model.Plugin).join(model.LicenseType).filter(model.License.user_id==user_id, model.License.available > 0).all()

def get_available(user_id):
    licenses = DBSession.query(model.License).filter(model.License.user_id==user_id, model.License.available > 0).all()

    list = []
    for i in licenses:
        list.append

class AssignmentForm(twf.Form):

    submit = twf.SubmitButton(value='Assign License')
    action = '/assign_license'
    show_errors = True

    def prepare(self):
        self.child.c.computer.options = [(i.id, str(i.id) + ":" + i.display_name) for i in get_computers(self.value.user_id)]
        self.child.c.license.options = [(i.License.id, str(i.License.id) + ":" + i.Plugin.display_name + ":" + i.LicenseType.display_name + (":floating" if i.License.floating else '' )) for i in get_licenses(self.value.user_id)]
        #self.child.c.count.options = [(i.id, i.display_name) for i in get_available(self.value.user_id)]
        super(AssignmentForm, self).prepare()

    class child(twf.TableLayout):

        hover_help = True

        computer = twf.SingleSelectField(help_text='Select a computer.', options=[], validator=twc.Required)
        license = twf.SingleSelectField(help_text='Select a license to assign.', options=[], validator=twc.Required)
        #count = twf.SingleSelectField(help_text='Number of licenses to assign.', options=[], validator=twc.Required)


def unlockComputer(obj):
    return  genshi.Markup('<form method="POST" action="%s" class="button-to"><input type="hidden" name="_method" value="Unlock" /><input class="delete-button" onclick="return confirm(\'Are you sure you want to unlock this computer?\');" value="Unlock" type="submit" style="background-color:transparent; float:left; border:0; color: #286571; display:inline; margin:0; padding:0;"/></form>' % url('/unlock_computer', params=dict(id=obj.Computer.id)))

admin_license_grid = twf.DataGrid(fields=[
    ('User id', 'User.user_id'),
    ('Email', 'User.user_name'),
    ('Plugin', 'Plugin.display_name'),
    ('License Type', 'LicenseType.display_name'),
    ('Count', 'License.count'),
    ('Available', 'License.available')
])


admin_computer_grid = twf.DataGrid(fields=[
    ('User id', 'User.user_id'),
    ('Email', 'User.user_name'),
    ('Computer id', 'Computer.id'),
    ('Computer Name', 'Computer.display_name'),
    ('Action', unlockComputer)
])

class CreateUserForm(twf.Form):

    submit = twf.SubmitButton(value='Create User')
    action = '/create_user'
    show_errors = True

    def prepare(self):
        #self.child.c.licenses.options = [(i.id, i.display_name) for i in DBSession.query(model.Plugin).all()]
        #self.child.c.license_type.options = [(i.id, i.display_name) for i in DBSession.query(model.LicenseType).all()]
        super(CreateUserForm, self).prepare()

    class child(twf.TableLayout):

        hover_help = True

        email_filter = twf.HiddenField()
        id_filter = twf.HiddenField()
        name = twf.TextField(help_text='Enter user name.', validator=twc.Required)
        login_email = twf.TextField(help_text='Enter a login email address.', validator=twc.EmailValidator(required=True))
        #licenses = twf.MultipleSelectField(help_text='Licenses to assign.', options=[])
        #license_type = twf.SingleSelectField(help_text='Licenes Type.', value=0, options=[], validator=twc.Required)
        #count = twf.SingleSelectField(help_text='Number of licenses.', value=1, options=[(i, i) for i in range(1,6)], validator=twc.Required)

class AssignLicensesForm(twf.Form):

    submit = twf.SubmitButton(value='Assign Licenses')
    action = '/assign_licences'
    show_errors = True

    def prepare(self):
        self.child.c.licenses.options = [(i.id, i.display_name) for i in DBSession.query(model.Plugin).all()]
        self.child.c.license_type.options = [(i.id, i.display_name) for i in DBSession.query(model.LicenseType).all()]
        super(AssignLicensesForm, self).prepare()

    class child(twf.TableLayout):

        hover_help = True

        email_filter = twf.HiddenField()
        id_filter = twf.HiddenField()
        user_Id= twf.TextField(help_text='Enter a user id.', validator=twc.IntValidator(required=True))
        licenses = twf.MultipleSelectField(help_text='Licenses to assign.', options=[], validator=twc.Required)
        license_type = twf.SingleSelectField(help_text='Licenes Type.', value=0, options=[], validator=twc.Required)
        count = twf.SingleSelectField(help_text='Number of licenses.', value=1, options=[(i, i) for i in range(1,6)], validator=twc.Required)


#Licence generation classes
#______________________________________________


class LicenseFormat:

    def __init__(self):
        self._plugins = ""
        self._num_plugs = 0

    def set_user_id(self, user_id):
        self._user_id = user_id

    def set_uuid1(self, uuid1):
        self._uuid1 = uuid1

    def set_uuid2(self, uuid2):
        self._uuid2 = uuid2

    def add_plugin(self, name, l_type, count, floating):
        self._plugins += name + "[" + str(l_type) + "," + str(count) + "," + str(floating) + "]"
        self._num_plugs += 1

    def format_license(self):
        return "num_plugs={" + str(self._num_plugs) + "}plugins={" + self._plugins + "}uuid1={" + self._uuid1 + "}uuid2={" + self._uuid2 + "}" + "user_id="+self._user_id

class LicenseClient:

    def __init__(self, host, port):
        self._HOST = host
        self._PORT = port
        self._ADDR = (self._HOST, self._PORT)
        self._BUFSIZE = 4096

        self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #5 second timeout before conenct will throw an error
        self._client.settimeout(5)
        self._client.connect(self._ADDR,)
        self._client.settimeout(None)

    def get_license(self, license):

        self._client.send(license)
        license = self._client.recv(self._BUFSIZE)
        return license

    def __del__(self):
        self._client.close()


#Controllers
#_________________________________________________________

class RootController(BaseController):

    secc = SecureController()
    admin = AdminController(model, DBSession, config_type=TGAdminConfig)

    error = ErrorController()


    def _before(self, *args, **kw):
        tmpl_context.project_name = "licensing_portal"

    #Redirect to login page
    @expose()
    def index(self):
        #If no logged into go to login, else
        redirect('login/')

    #Instructions page
    @expose('licensing_portal.templates.instructions')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def instructions(self):
        return dict(page='instructions')

    #Downloads page
    @expose('licensing_portal.templates.downloads')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def downloads(self):
        return dict(page='downloads')

    #Serve file for download
    @expose()
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def serve_file(self, file_path=None, file_name=None):
        import paste.fileapp
        f = paste.fileapp.FileApp('/home/authorityfx/plugin_downloads/' + file_path + file_name, **{'Content-Disposition': 'attachment; filename=' + file_name})
        from tg import use_wsgi_app
        return use_wsgi_app(f)

    #Settings page
    @expose('licensing_portal.templates.settings')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def settings(self, **kwargs):
        return dict(page='settings', form=SettingsForm, data=kwargs)

    @expose('licensing_portal.templates.settings')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    @validate(form=SettingsForm)
    def update_settings_error(self, **kwargs):
        return dict(page='settings', form=SettingsForm, data=kwargs)

    #Update user credentials
    @expose('licensing_portal.templates.settings')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    @validate(form=SettingsForm, error_handler=update_settings_error)
    def update_settings(self, **kwargs):

        fail = False
        changed = False
        update_password = False
        update_email = False
        msg = ''

        #Get user
        user_name = request.identity['repoze.who.userid']
        user = DBSession.query(model.User).filter(model.User.user_name==user_name).first()

        #Check if current password matches
        if user.validate_password(kwargs['current_password']) == False:
            fail = True
            msg = msg + "  Wrong password!"

        #Update name
        if fail != True and 'name' in kwargs:

            if len(kwargs['name']) > 0:

                #Hash new password
                user.display_name = kwargs['name']
                msg = msg + "  Successfully changed name."
                changed = True

        #Update email
        if fail != True and 'login_email' in kwargs:

            if len(kwargs['login_email']) > 0:

                new_email = kwargs['login_email'].lower()

                count = DBSession.query(model.User).filter(model.User.user_name==new_email).count()

                if count == 0:
                    user.user_name = new_email
                    msg = msg + '  Successfully changed login email.'
                    changed = True
                else:
                    fail = True
                    msg = msg + '  Email address already assigned.'


        #Update passwood
        if fail != True and 'new_password' in kwargs:

            if len(kwargs['new_password']) > 0:

                #Hash new password
                user._set_password(kwargs['new_password'])
                msg = msg + "  Successfully changed password."
                changed = True


        #if no errors write to database
        if fail != True and changed == True:
            DBSession.flush()
            flash(msg.strip())
            redirect('/logout_handler')
        elif fail != True and changed == False:
            flash('No Updates', 'warning')
            return dict(page='settings', form=SettingsForm, data=kwargs)
        else:
            flash(msg.strip(), 'error')
            return dict(page='settings', form=SettingsForm, data=kwargs)


#Admin controllers
#_________________________________________


    def get_admin_panel_data(self, **kwargs):

        user_id_query = DBSession.query(model.User.user_id)

        if 'email_filter' in kwargs:
            if kwargs['email_filter'] != '':
                user_id_query = user_id_query.filter(model.User.user_name==kwargs['email_filter'])
        else:
            kwargs['email_filter'] = ''

        if 'id_filter' in kwargs:
            if kwargs['id_filter'] != '':
                user_id_query = user_id_query.filter(model.User.user_id==kwargs['id_filter'])
        else:
            kwargs['id_filter'] = ''

        if user_id_query.first():
            user_id = user_id_query.first().user_id
        else:
            user_id = 1

        admin_license_data = DBSession.query(model.User, model.License, model.Plugin, model.LicenseType).join(model.License).join(model.Plugin).join(model.LicenseType).filter(model.User.user_id==user_id)

        admin_computer_data = DBSession.query(model.User, model.Computer).join(model.Computer).filter(model.User.user_id==user_id)


        return dict(page='admin_panel', admin_computer_data=admin_computer_data[:10], admin_license_data=admin_license_data, admin_license_grid=admin_license_grid, admin_computer_grid=admin_computer_grid, assign_licences_form=AssignLicensesForm, create_user_form=CreateUserForm, data=kwargs)

    #Admin panel
    @expose('licensing_portal.templates.admin_panel')
    @require(predicates.has_permission('manage'))
    def admin_panel(self, **kwargs):
          return self.get_admin_panel_data(**kwargs)

    #Create user error
    @expose('licensing_portal.templates.admin_panel')
    @require(predicates.has_permission('manage'))
    @validate(form=CreateUserForm)
    def create_user_error(self, **kwargs):
        return self.get_admin_panel_data(**kwargs)

    #Create user
    @expose('licensing_portal.templates.admin_panel')
    @require(predicates.has_permission('manage'))
    @validate(form=CreateUserForm, error_handler=create_user_error)
    def create_user(self, **kwargs):

        name = kwargs['name']
        email = kwargs['login_email'].lower()

        if DBSession.query(model.User).filter(model.User.user_name==email).count() > 0:
            flash(email + ' already exists!', 'error')
            kwargs['login_email']=''
            return self.admin_panel(**kwargs)
            #redirect('/admin_panel', kwargs)

        password = ''.join(random.choice(string.letters + string.digits + string.punctuation) for x in xrange(8))

        u = model.User()
        u.user_name = email
        u.display_name = name
        u.password = password

        licensing_portal_url = "licensing.authorityfx.com"

        subject = "New Authority FX Licensing Portal Account"
        body =    "Dear " + name + ",\n" \
                + "\n" \
                + "Please login into your new Authority FX licensing portal account with the following credentials: \n" \
                + "\n" \
                + licensing_portal_url + "\n" \
                + "\n" \
                + "username: " + email + "\n" \
                + "password: " + password + "\n" \
                + "\n" \
                + "We suggest that you change you password upon first login.\n" \
                + "\n" \
                + "Remember that all purchases are added into our licensing portal under the email address provided at checkout.  "\
                + "If you want to make puchases using another email address, please ensure that you change your login email via the " \
                + "settings page prior to making any new purchases.\n" \
                + "\n" \
                + "Thanks!"

        try:
            sender = SendMail()
            sender.send_mail(email, subject, body)
            DBSession.add(u)
            DBSession.flush()
            flash(email + ' added and notified via email.')
        except Exception, e:
            flash(('Could not send new login to ' + name + ", " + email + ": " + str(e)), 'error')

        redirect('/admin_panel')


    #Assign licenses error
    @expose('licensing_portal.templates.admin_panel')
    @require(predicates.has_permission('manage'))
    @validate(form=AssignLicensesForm)
    def assign_licences_error(self, **kwargs):
        return self.get_admin_panel_data(**kwargs)

    #Assign licenses
    @expose('licensing_portal.templates.admin_panel')
    @require(predicates.has_permission('manage'))
    @validate(form=AssignLicensesForm, error_handler=create_user_error)
    def assign_licences(self, **kwargs):

        user_id = kwargs['user_Id']
        licenses = kwargs['licenses']
        license_type = kwargs['license_type']
        count = kwargs['count']

        for license in licenses:
            flash(license)

        redirect('/admin_panel')




#Manage controllers
#_________________________________________

    #Create license
    @expose()
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def create_license(self, **data):

        user_name = request.identity['repoze.who.userid']
        user_id = DBSession.query(model.User.user_id).filter(model.User.user_name==user_name).first().user_id

        #Make sure that the computer_id belongs to user who is loggned in and that it has assignments
        if DBSession.query(model.Computer).filter(model.Computer.id==data['id'], model.Computer.user_id==user_id).count() < 1  or DBSession.query(model.Assignment).filter(model.Assignment.computer_id==data['id'], model.Assignment.user_id==user_id).count() < 1:
            flash(('This incident has been reported'), 'error')
            redirect('/manage')

        assignments = DBSession.query(model.Assignment.id).join(model.Computer).filter(model.Computer.id==data['id']).all()

        grouped_assignments = DBSession.query(func.sum(model.Assignment.count).label('count_sum'), model.Assignment, model.Computer, model.License).join(model.Computer).join(model.License).filter(model.Computer.id==data['id']).group_by(model.License.id).all()

        plain_license = LicenseFormat()

        for assignment in grouped_assignments:
            floating = 0
            if assignment.License.floating == True:
                floating = 1
            plain_license.add_plugin(assignment.License.plugin_id, assignment.License.l_type, assignment.count_sum, floating)

        plain_license.set_uuid1(grouped_assignments[0].Computer.uuid1)
        plain_license.set_uuid2(grouped_assignments[0].Computer.uuid2)

        plain_license.set_user_id(grouped_assignments[0].Computer.user_id)

        try:
            afx_ip = DBSession.query(model.Settings.afx_ip).first().afx_ip
            client = LicenseClient(afx_ip, 31568)
            license = client.get_license(plain_license.format_license())

            if license.find('Licensing Error') >= 0:
                flash(_("Licensing Error. Please email plugins@authorityfx.com"), 'warning')
                redirect('/manage')
            else:
                for assignment in assignments:
                    #Lock assignment
                    a = DBSession.query(model.Assignment).filter(model.Assignment.id==assignment.id).first()
                    a.locked = True
                    DBSession.flush()

                #Serve license file
                rh = response.headers
                rh['Content-Type'] = 'application/csv; charset=utf-8'
                disposition = 'attachment; filename="afx-license.dat"'
                rh['Content-disposition'] = disposition
                return license
        except:
            flash(_("Licensing Error. Please email plugins@authorityfx.com"), 'warning')
            redirect('/manage')

    #Delete Computer
    @expose()
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def delete_computer(self, **data):

        user_name = request.identity['repoze.who.userid']
        user_id = DBSession.query(model.User.user_id).filter(model.User.user_name==user_name).first().user_id

        #Report if no assignments and cbelongs to user who is loggned in
        if DBSession.query(model.Computer).filter(model.Computer.id==data['id'], model.Computer.user_id==user_id).count() < 1  or DBSession.query(model.Assignment).filter(model.Assignment.computer_id==data['id'], model.Assignment.user_id==user_id).count() > 0:
            flash(('This incident has been reported'), 'error')
            redirect('/manage')

        name = DBSession.query(model.Computer.display_name).filter(model.Computer.id==data['id']).first()[0]

        q = DBSession.query(model.Computer).filter(model.Computer.id==data['id']).delete()

        flash("Computer deleted: '" + name + "'")
        redirect('/manage')

    #Delete assignment
    @expose()
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def delete_assignment(self, **data):

        user_name = request.identity['repoze.who.userid']
        user_id = DBSession.query(model.User.user_id).filter(model.User.user_name==user_name).first().user_id

        #Report if not user who is logged in
        if DBSession.query(model.License).join(model.Assignment).filter(model.Assignment.id==data['id'], model.License.user_id==user_id).count() < 1:
            flash(('This incident has been reported'), 'error')
            redirect('/manage')

        locked = DBSession.query(model.Assignment.locked).filter(model.Assignment.id==data['id']).first().locked

        if locked == True:
            flash(_('Cannot delete. Assignment already redeemed.'), 'warning')
        else:
            license = DBSession.query(model.License).join(model.Assignment).filter(model.Assignment.id==data['id']).first()

            license.available = license.available + DBSession.query(model.Assignment).filter(model.Assignment.id==data['id']).first().count

            q = DBSession.query(model.Assignment).filter(model.Assignment.id==data['id']).delete()

            DBSession.flush()

            flash('Assignment deleted')

        redirect('/manage')


    #Query manage data
    def get_manage_data(self):
        user_name = request.identity['repoze.who.userid']
        user_id = DBSession.query(model.User.user_id).filter(model.User.user_name==user_name).first()
        license_data = DBSession.query(model.License, model.Plugin, model.LicenseType).join(model.User).join(model.Plugin).join(model.LicenseType).filter(model.User.user_name==user_name)
        computer_data = DBSession.query(model.Computer).join(model.User).filter(model.User.user_name==user_name)
        assignment_data = DBSession.query(model.Assignment, model.Computer, model.Plugin).join(model.Computer).join(model.License).join(model.Plugin).filter(model.License.user_id==user_id.user_id)
        computer_list = DBSession.query(model.Computer).join(model.User).filter(model.User.user_name==user_name).all()

        return dict(page='manage', add_computer_form=AddComputerForm, assignment_form=AssignmentForm, license_grid=license_grid, computer_grid=computer_grid, assignment_grid=assignment_grid, license_data=license_data, computer_data=computer_data, assignment_data=assignment_data, user_id=user_id)


    #Manage page
    @expose('licensing_portal.templates.manage')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    def manage(self, **kwargs):
        return self.get_manage_data()


    #Add computer error
    @expose('licensing_portal.templates.manage')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    @validate(form=SettingsForm)
    def add_computer_error(self, **kwargs):
        return self.get_manage_data()

    #Add computer
    @expose('licensing_portal.templates.manage')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    @validate(form=AddComputerForm, error_handler=add_computer_error)
    def add_computer(self, **kwargs):

        user_name = request.identity['repoze.who.userid']
        user_id = DBSession.query(model.User.user_id).filter(model.User.user_name==user_name).first().user_id

        c = model.Computer()
        c.user_id = user_id
        c.display_name = kwargs['name']
        c.uuid1 = kwargs['mac']
        c.uuid2 = u'none'
        model.DBSession.add(c)

        model.DBSession.flush()

        flash("Computer added: '" + c.display_name + "'")
        redirect('/manage')


    #Assign license error
    @expose('licensing_portal.templates.manage')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    @validate(form=AssignmentForm)
    def assign_license_error(self, **kwargs):
        return self.get_manage_data()

    #Assign license
    @expose('licensing_portal.templates.manage')
    @require(predicates.not_anonymous(msg='Must be logged in.'))
    @validate(form=AssignmentForm, error_handler=assign_license_error)
    def assign_license(self, **kwargs):

        user_name = request.identity['repoze.who.userid']
        user_id = DBSession.query(model.User.user_id).filter(model.User.user_name==user_name).first().user_id

        #Report if computer or license don't belong to user who is logged in and available > 0
        if DBSession.query(model.Computer).filter(model.Computer.id==kwargs['computer'], model.Computer.user_id==user_id).count() < 1  or DBSession.query(model.License).filter(model.License.id==kwargs['license'], model.License.user_id==user_id).count() < 1 or DBSession.query(model.License.available).filter(model.License.id==kwargs['license'], model.License.user_id==user_id).first().available < 1:
            flash(('This incident has been reported'), 'error')
            redirect('/manage')

        a = model.Assignment()
        a.user_id = user_id
        a.license_id = kwargs['license']
        a.computer_id = kwargs['computer']
        a.count = 1
        a.locked = False

        model.DBSession.add(a)

        license = DBSession.query(model.License).filter(model.License.id==a.license_id).first()
        license.available = license.available - a.count


        model.DBSession.flush()

        flash("Assignment added.")
        redirect('/manage')


    #Login page
    @expose('licensing_portal.templates.login')
    def login(self, came_from=lurl('/')):
        login_counter = request.environ.get('repoze.who.logins', 0)
        if login_counter > 0:
            flash(_('Wrong credentials'), 'warning')
        return dict(page='login', login_counter=str(login_counter), came_from=came_from)

    @expose()
    def post_login(self, came_from=lurl('/')):

        if not request.identity:
            login_counter = request.environ.get('repoze.who.logins', 0) + 1
            redirect('/login',
                params=dict(came_from=came_from, __logins=login_counter))
        user_name = request.identity['repoze.who.userid']
        display_name = str(DBSession.query(model.User.display_name).filter(model.User.user_name==user_name).first()[0])
        flash(_('Welcome back, %s!') % display_name)
        redirect('/manage')

    @expose()
    def post_logout(self, came_from=lurl('/')):
        redirect('login/')

