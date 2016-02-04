# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (C) 2012-2016, Ryan P. Wilson
#
#     Authority FX, Inc.
#     www.authorityfx.com

# -*- coding: utf-8 -*-
"""Setup the licensing-portal application"""

import logging
from tg import config
from licensing_portal import model
import transaction

def bootstrap(command, conf, vars):
    """Place any commands to setup licensing_portal here"""

    # <websetup.bootstrap.before.auth
    from sqlalchemy.exc import IntegrityError
    try:
        u = model.User()
        u.user_name = u'admin'
        u.display_name = u'admin'
        u.password = u'admin'

        model.DBSession.add(u)

        g = model.Group()
        g.group_name = u'managers'
        g.display_name = u'Admin Group'

        g.users.append(u)

        model.DBSession.add(g)

        p = model.Permission()
        p.permission_name = u'manage'
        p.description = u'This permission give an administrative right to the bearer'
        p.groups.append(g)

        model.DBSession.add(p)

        #Settings
        s = model.Settings()
        s.afx_ip = '67.70.80.214'
        model.DBSession.add(s)

        #Add plugins
        p = model.Plugin()
        p.id = 'chroma_key'
        p.display_name = 'Chroma Key'
        model.DBSession.add(p)

        p = model.Plugin()
        p.id = 'glow'
        p.display_name = 'Glow'
        model.DBSession.add(p)

        p = model.Plugin()
        p.id = 'lens_glow'
        p.display_name = 'Lens Glow'
        model.DBSession.add(p)

        p = model.Plugin()
        p.id = 'defocus'
        p.display_name = 'Defocus'
        model.DBSession.add(p)

        p = model.Plugin()
        p.id = 'z_defocus'
        p.display_name = 'Z Defocus'
        model.DBSession.add(p)

        p = model.Plugin()
        p.id = 'soft_clip'
        p.display_name = 'Soft Clip'
        model.DBSession.add(p)

        p = model.Plugin()
        p.id = 'clamp'
        p.display_name = 'Clamp'
        model.DBSession.add(p)

        p = model.Plugin()
        p.id = 'desaturate'
        p.display_name = 'Desaturate'
        model.DBSession.add(p)


        #Add license types
        t = model.LicenseType()
        t.id = '0'
        t.display_name = 'Workstation'
        model.DBSession.add(t)

        t = model.LicenseType()
        t.id = '1'
        t.display_name = 'Render'
        model.DBSession.add(t)

        t = model.LicenseType()
        t.id = '2'
        t.display_name = 'Trial'
        model.DBSession.add(t)


        model.DBSession.flush()
        transaction.commit()
    except IntegrityError:
        print 'Warning, there was a problem adding your auth data, it may have already been added:'
        import traceback
        print traceback.format_exc()
        transaction.abort()
        print 'Continuing with bootstrapping...'

    # <websetup.bootstrap.after.auth>
