# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import datetime
import logging
import re
from typing import Dict, List, Set, Tuple

from flask import g, session, url_for
from flask_appbuilder.const import (
    AUTH_DB,
    AUTH_LDAP,
    AUTH_OAUTH,
    AUTH_OID,
    AUTH_REMOTE_USER,
    LOGMSG_WAR_SEC_LOGIN_FAILED,
    LOGMSG_WAR_SEC_NO_USER,
)
from flask_appbuilder.security.api import SecurityApi
from flask_appbuilder.security.registerviews import (
    RegisterUserDBView,
    RegisterUserOAuthView,
    RegisterUserOIDView,
)
from flask_appbuilder.security.views import (
    AuthDBView,
    AuthLDAPView,
    AuthOAuthView,
    AuthOIDView,
    AuthRemoteUserView,
    PermissionModelView,
    PermissionViewModelView,
    RegisterUserModelView,
    ResetMyPasswordView,
    ResetPasswordView,
    RoleModelView,
    UserDBModelView,
    UserInfoEditView,
    UserLDAPModelView,
    UserOAuthModelView,
    UserOIDModelView,
    UserRemoteUserModelView,
    UserStatsChartView,
    ViewMenuModelView,
)
from flask_babel import lazy_gettext as _
from flask_jwt_extended import JWTManager, current_user as current_user_jwt
from flask_login import LoginManager, current_user
from werkzeug.security import generate_password_hash

from airflow.www.fab_security.backend import AuthBackendDB, AuthBackendLDAP, AuthBackendOAuth, AuthBackendOpenID

log = logging.getLogger(__name__)


def _oauth_tokengetter(token=None):
    """
    Default function to return the current user oauth token
    from session cookie.
    """
    token = session.get("oauth")
    log.debug(f"Token Get: {token}")
    return token


class BaseSecurityManager:
    appbuilder = None
    """The appbuilder instance for the current security manager."""
    auth_view = None
    """ The obj instance for authentication view """
    user_view = None
    """ The obj instance for user view """
    registeruser_view = None
    """ The obj instance for registering user view """
    lm = None
    """ Flask-Login LoginManager """
    jwt_manager = None
    """ Flask-JWT-Extended """
    oid = None
    """ Flask-OpenID OpenID """
    user_model = None
    """ Override to set your own User Model """
    role_model = None
    """ Override to set your own Role Model """
    permission_model = None
    """ Override to set your own Permission Model """
    viewmenu_model = None
    """ Override to set your own ViewMenu Model """
    permissionview_model = None
    """ Override to set your own PermissionView Model """
    registeruser_model = None
    """ Override to set your own RegisterUser Model """

    oauth = None
    """ Flask-OAuth """
    oauth_remotes = None
    """ OAuth email whitelists """
    oauth_whitelists = {}
    """ Initialized (remote_app) providers dict {'provider_name', OBJ } """
    oauth_tokengetter = _oauth_tokengetter
    """ OAuth tokengetter function override to implement your own tokengetter method """
    oauth_user_info = None

    userdbmodelview = UserDBModelView
    """ Override if you want your own user db view """
    userldapmodelview = UserLDAPModelView
    """ Override if you want your own user ldap view """
    useroidmodelview = UserOIDModelView
    """ Override if you want your own user OID view """
    useroauthmodelview = UserOAuthModelView
    """ Override if you want your own user OAuth view """
    userremoteusermodelview = UserRemoteUserModelView
    """ Override if you want your own user REMOTE_USER view """
    registerusermodelview = RegisterUserModelView

    authdbview = AuthDBView
    """ Override if you want your own Authentication DB view """
    authldapview = AuthLDAPView
    """ Override if you want your own Authentication LDAP view """
    authoidview = AuthOIDView
    """ Override if you want your own Authentication OID view """
    authoauthview = AuthOAuthView
    """ Override if you want your own Authentication OAuth view """
    authremoteuserview = AuthRemoteUserView
    """ Override if you want your own Authentication REMOTE_USER view """

    registeruserdbview = RegisterUserDBView
    """ Override if you want your own register user db view """
    registeruseroidview = RegisterUserOIDView
    """ Override if you want your own register user OpenID view """
    registeruseroauthview = RegisterUserOAuthView
    """ Override if you want your own register user OAuth view """

    resetmypasswordview = ResetMyPasswordView
    """ Override if you want your own reset my password view """
    resetpasswordview = ResetPasswordView
    """ Override if you want your own reset password view """
    userinfoeditview = UserInfoEditView
    """ Override if you want your own User information edit view """

    # API
    security_api = SecurityApi
    """ Override if you want your own Security API login endpoint """

    rolemodelview = RoleModelView
    permissionmodelview = PermissionModelView
    userstatschartview = UserStatsChartView
    viewmenumodelview = ViewMenuModelView
    permissionviewmodelview = PermissionViewModelView

    def __init__(self, appbuilder):
        self.appbuilder = appbuilder
        app = self.appbuilder.get_app
        # Base Security Config
        app.config.setdefault("AUTH_ROLE_ADMIN", "Admin")
        app.config.setdefault("AUTH_ROLE_PUBLIC", "Public")
        app.config.setdefault("AUTH_TYPE", AUTH_DB)
        # Self Registration
        app.config.setdefault("AUTH_USER_REGISTRATION", False)
        app.config.setdefault("AUTH_USER_REGISTRATION_ROLE", self.auth_role_public)
        app.config.setdefault("AUTH_USER_REGISTRATION_ROLE_JMESPATH", None)
        # Role Mapping
        app.config.setdefault("AUTH_ROLES_MAPPING", {})
        app.config.setdefault("AUTH_ROLES_SYNC_AT_LOGIN", False)

        # LDAP Config
        if self.auth_type == AUTH_LDAP:
            self.backend = AuthBackendLDAP(app, self)
        if self.auth_type == AUTH_OID:
            self.backend = AuthBackendOpenID(app, self)
        if self.auth_type == AUTH_OAUTH:
            self.backend = AuthBackendOAuth(app, self)
        if self.auth_type == AUTH_DB:
            self.backend = AuthBackendDB(app, self)

        self._builtin_roles = self.create_builtin_roles()
        # Setup Flask-Login
        self.lm = self.create_login_manager(app)

        # Setup Flask-Jwt-Extended
        self.jwt_manager = self.create_jwt_manager(app)

    def create_login_manager(self, app) -> LoginManager:
        """
        Override to implement your custom login manager instance

        :param app: Flask app
        """
        lm = LoginManager(app)
        lm.login_view = "login"
        lm.user_loader(self.load_user)
        return lm

    def create_jwt_manager(self, app) -> JWTManager:
        """
        Override to implement your custom JWT manager instance

        :param app: Flask app
        """
        jwt_manager = JWTManager()
        jwt_manager.init_app(app)
        jwt_manager.user_loader_callback_loader(self.load_user_jwt)
        return jwt_manager

    def create_builtin_roles(self):
        return self.appbuilder.get_app.config.get("FAB_ROLES", {})

    def get_roles_from_keys(self, role_keys: List[str]) -> Set[role_model]:
        """
        Construct a list of FAB role objects, from a list of keys.

        NOTE:
        - keys are things like: "LDAP group DNs" or "OAUTH group names"
        - we use AUTH_ROLES_MAPPING to map from keys, to FAB role names

        :param role_keys: the list of FAB role keys
        :return: a list of RoleModelView
        """
        _roles = set()
        _role_keys = set(role_keys)
        for role_key, fab_role_names in self.auth_roles_mapping.items():
            if role_key in _role_keys:
                for fab_role_name in fab_role_names:
                    fab_role = self.find_role(fab_role_name)
                    if fab_role:
                        _roles.add(fab_role)
                    else:
                        log.warning(f"Can't find role specified in AUTH_ROLES_MAPPING: {fab_role_name}")
        return _roles

    @property
    def get_url_for_registeruser(self):
        # TODO: Maybe delete?
        return url_for(f"{self.registeruser_view.endpoint}.{self.registeruser_view.default_view}")

    @property
    def get_user_datamodel(self):
        return self.user_view.datamodel

    @property
    def get_register_user_datamodel(self):
        return self.registerusermodelview.datamodel

    @property
    def builtin_roles(self):
        return self._builtin_roles

    @property
    def auth_type(self):
        return self.appbuilder.get_app.config["AUTH_TYPE"]

    @property
    def auth_username_ci(self):
        return self.appbuilder.get_app.config.get("AUTH_USERNAME_CI", True)

    @property
    def auth_role_admin(self):
        return self.appbuilder.get_app.config["AUTH_ROLE_ADMIN"]

    @property
    def auth_role_public(self):
        return self.appbuilder.get_app.config["AUTH_ROLE_PUBLIC"]

    @property
    def auth_user_registration(self):
        return self.appbuilder.get_app.config["AUTH_USER_REGISTRATION"]

    @property
    def auth_user_registration_role(self):
        return self.appbuilder.get_app.config["AUTH_USER_REGISTRATION_ROLE"]

    @property
    def auth_roles_mapping(self) -> Dict[str, List[str]]:
        return self.appbuilder.get_app.config["AUTH_ROLES_MAPPING"]

    @property
    def auth_roles_sync_at_login(self) -> bool:
        return self.appbuilder.get_app.config["AUTH_ROLES_SYNC_AT_LOGIN"]

    @property
    def openid_providers(self):
        return self.appbuilder.get_app.config["OPENID_PROVIDERS"]

    @property
    def current_user(self):
        if current_user.is_authenticated:
            return g.user
        elif current_user_jwt:
            return current_user_jwt

    def register_views(self):
        if not self.appbuilder.app.config.get("FAB_ADD_SECURITY_VIEWS", True):
            return
        # Security APIs
        self.appbuilder.add_api(self.security_api)

        if self.auth_user_registration:
            if self.auth_type == AUTH_DB:
                self.registeruser_view = self.registeruserdbview()
            elif self.auth_type == AUTH_OID:
                self.registeruser_view = self.registeruseroidview()
            elif self.auth_type == AUTH_OAUTH:
                self.registeruser_view = self.registeruseroauthview()
            if self.registeruser_view:
                self.appbuilder.add_view_no_menu(self.registeruser_view)

        self.appbuilder.add_view_no_menu(self.resetpasswordview())
        self.appbuilder.add_view_no_menu(self.resetmypasswordview())
        self.appbuilder.add_view_no_menu(self.userinfoeditview())

        if self.auth_type == AUTH_DB:
            self.user_view = self.userdbmodelview
            self.auth_view = self.authdbview()

        elif self.auth_type == AUTH_LDAP:
            self.user_view = self.userldapmodelview
            self.auth_view = self.authldapview()
        elif self.auth_type == AUTH_OAUTH:
            self.user_view = self.useroauthmodelview
            self.auth_view = self.authoauthview()
        elif self.auth_type == AUTH_REMOTE_USER:
            self.user_view = self.userremoteusermodelview
            self.auth_view = self.authremoteuserview()
        else:
            self.user_view = self.useroidmodelview
            self.auth_view = self.authoidview()
            if self.auth_user_registration:
                pass
                # self.registeruser_view = self.registeruseroidview()
                # self.appbuilder.add_view_no_menu(self.registeruser_view)

        self.appbuilder.add_view_no_menu(self.auth_view)

        self.user_view = self.appbuilder.add_view(
            self.user_view,
            "List Users",
            icon="fa-user",
            label=_("List Users"),
            category="Security",
            category_icon="fa-cogs",
            category_label=_("Security"),
        )

        role_view = self.appbuilder.add_view(
            self.rolemodelview,
            "List Roles",
            icon="fa-group",
            label=_("List Roles"),
            category="Security",
            category_icon="fa-cogs",
        )
        role_view.related_views = [self.user_view.__class__]

        if self.userstatschartview:
            self.appbuilder.add_view(
                self.userstatschartview,
                "User's Statistics",
                icon="fa-bar-chart-o",
                label=_("User's Statistics"),
                category="Security",
            )
        if self.auth_user_registration:
            self.appbuilder.add_view(
                self.registerusermodelview,
                "User's Statistics",
                icon="fa-user-plus",
                label=_("User Registrations"),
                category="Security",
            )
        self.appbuilder.menu.add_separator("Security")
        if self.appbuilder.app.config.get("FAB_ADD_SECURITY_PERMISSION_VIEW", True):
            self.appbuilder.add_view(
                self.permissionmodelview,
                "Base Permissions",
                icon="fa-lock",
                label=_("Base Permissions"),
                category="Security",
            )
        if self.appbuilder.app.config.get("FAB_ADD_SECURITY_VIEW_MENU_VIEW", True):
            self.appbuilder.add_view(
                self.viewmenumodelview,
                "Views/Menus",
                icon="fa-list-alt",
                label=_("Views/Menus"),
                category="Security",
            )
        if self.appbuilder.app.config.get("FAB_ADD_SECURITY_PERMISSION_VIEWS_VIEW", True):
            self.appbuilder.add_view(
                self.permissionviewmodelview,
                "Permission on Views/Menus",
                icon="fa-link",
                label=_("Permission on Views/Menus"),
                category="Security",
            )

    def create_db(self):
        """
        Setups the DB, creates admin and public roles if they don't exist.
        """
        roles_mapping = self.appbuilder.get_app.config.get("FAB_ROLES_MAPPING", {})
        for pk, name in roles_mapping.items():
            self.update_role(pk, name)
        for role_name in self.builtin_roles:
            self.add_role(role_name)
        if self.auth_role_admin not in self.builtin_roles:
            self.add_role(self.auth_role_admin)
        self.add_role(self.auth_role_public)
        if self.count_users() == 0:
            log.warning(LOGMSG_WAR_SEC_NO_USER)

    def reset_password(self, userid, password):
        """
        Change/Reset a user's password for authdb.
        Password will be hashed and saved.

        :param userid:
            the user.id to reset the password
        :param password:
            The clear text password to reset and save hashed on the db
        """
        user = self.get_user_by_id(userid)
        user.password = generate_password_hash(password)
        self.update_user(user)

    def update_user_auth_stat(self, user, success=True):
        """
        Update authentication successful to user.

        :param user:
            The authenticated user model
        :param success:
            Default to true, if false increments fail_login_count on user model
        """
        if not user.login_count:
            user.login_count = 0
        if not user.fail_login_count:
            user.fail_login_count = 0
        if success:
            user.login_count += 1
            user.fail_login_count = 0
        else:
            user.fail_login_count += 1
        user.last_login = datetime.datetime.now()
        self.update_user(user)

    def auth_user_db(self, username, password):
        """
        Method for authenticating user, auth db style

        :param username:
            The username or registered email address
        :param password:
            The password, will be tested against hashed password on db
        """
        return self.backend.auth_user_db(username, password)

    def auth_user_oid(self, email):
        """
        OpenID user Authentication

        :param email: user's email to authenticate
        :type self: User model
        """
        user = self.find_user(email=email)
        if user is None or (not user.is_active):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(email))
            return None
        else:
            self.update_user_auth_stat(user)
            return user

    def auth_user_remote_user(self, username):
        """
        REMOTE_USER user Authentication

        :param username: user's username for remote auth
        :type self: User model
        """
        user = self.find_user(username=username)

        # User does not exist, create one if auto user registration.
        if user is None and self.auth_user_registration:
            user = self.add_user(
                # All we have is REMOTE_USER, so we set
                # the other fields to blank.
                username=username,
                first_name=username,
                last_name="-",
                email=username + "@email.notfound",
                role=self.find_role(self.auth_user_registration_role),
            )

        # If user does not exist on the DB and not auto user registration,
        # or user is inactive, go away.
        elif user is None or (not user.is_active):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
            return None

        self.update_user_auth_stat(user)
        return user

    def is_item_public(self, permission_name, view_name):
        """
        Check if view has public permissions

        :param permission_name:
            the permission: can_show, can_edit...
        :param view_name:
            the name of the class view (child of BaseView)
        """
        permissions = self.get_public_permissions()
        if permissions:
            for i in permissions:
                if (view_name == i.view_menu.name) and (permission_name == i.permission.name):
                    return True
            return False
        else:
            return False

    def _has_access_builtin_roles(self, role, action_name: str, resource_name: str) -> bool:
        """
        Checks permission on builtin role
        """
        builtin_perms = self.builtin_roles.get(role.name, [])
        for perm in builtin_perms:
            _resource_name = perm[0]
            _action_name = perm[1]
            if re.match(_resource_name, resource_name) and re.match(_action_name, action_name):
                return True
        return False

    def _has_view_access(self, user: object, permission_name: str, view_name: str) -> bool:
        roles = user.roles
        db_role_ids = list()
        # First check against builtin (statically configured) roles
        # because no database query is needed
        for role in roles:
            if role.name in self.builtin_roles:
                if self._has_access_builtin_roles(role, permission_name, view_name):
                    return True
            else:
                db_role_ids.append(role.id)

        # If it's not a builtin role check against database store roles
        return self.exist_permission_on_roles(view_name, permission_name, db_role_ids)

    def get_user_roles(self, user) -> List[object]:
        """
        Get current user roles, if user is not authenticated returns the public role
        """
        if not user.is_authenticated:
            return [self.get_public_role()]
        return user.roles

    def get_role_permissions(self, role) -> Set[Tuple[str, str]]:
        """
        Get all permissions for a certain role
        """
        result = set()
        if role.name in self.builtin_roles:
            for permission in self.builtin_roles[role.name]:
                result.add((permission[1], permission[0]))
        else:
            for permission in self.get_db_role_permissions(role.id):
                result.add((permission.permission.name, permission.view_menu.name))
        return result

    def get_user_permissions(self, user) -> Set[Tuple[str, str]]:
        """
        Get all permissions from the current user
        """
        roles = self.get_user_roles(user)
        result = set()
        for role in roles:
            result.update(self.get_role_permissions(role))
        return result

    def _get_user_permission_view_menus(
        self, user: object, action_name: str, resource_names: List[str]
    ) -> Set[str]:
        """
        Return a set of view menu names with a certain permission name
        that a user has access to. Mainly used to fetch all menu permissions
        on a single db call, will also check public permissions and builtin roles
        """
        db_role_ids = list()
        if user is None:
            # include public role
            roles = [self.get_public_role()]
        else:
            roles = user.roles
        # First check against builtin (statically configured) roles
        # because no database query is needed
        result = set()
        for role in roles:
            if role.name in self.builtin_roles:
                for resource_name in resource_names:
                    if self._has_access_builtin_roles(role, action_name, resource_name):
                        result.add(resource_name)
            else:
                db_role_ids.append(role.id)
        # Then check against database-stored roles
        resource_names = [
            perm.view_menu.name for perm in self.find_roles_permission_view_menus(action_name, db_role_ids)
        ]
        result.update(resource_names)
        return result

    def has_access(self, permission_name, view_name):
        """
        Check if current user or public has access to view or menu
        """
        if current_user.is_authenticated:
            return self._has_view_access(g.user, permission_name, view_name)
        elif current_user_jwt:
            return self._has_view_access(current_user_jwt, permission_name, view_name)
        else:
            return self.is_item_public(permission_name, view_name)

    def get_user_menu_access(self, menu_names: List[str] = None) -> Set[str]:
        if current_user.is_authenticated:
            return self._get_user_permission_view_menus(g.user, "menu_access", resource_names=menu_names)
        elif current_user_jwt:
            return self._get_user_permission_view_menus(
                current_user_jwt, "menu_access", resource_names=menu_names
            )
        else:
            return self._get_user_permission_view_menus(None, "menu_access", resource_names=menu_names)

    def add_permissions_view(self, base_permissions, view_menu):
        """
        Adds a permission on a view menu to the backend

        :param base_permissions:
            list of permissions from view (all exposed methods):
             'can_add','can_edit' etc...
        :param view_menu:
            name of the view or menu to add
        """
        view_menu_db = self.create_resource(view_menu)
        perm_views = self.get_resource_permissions(view_menu_db)

        if not perm_views:
            # No permissions yet on this view
            for permission in base_permissions:
                pv = self.create_permission(permission, view_menu)
                if self.auth_role_admin not in self.builtin_roles:
                    role_admin = self.find_role(self.auth_role_admin)
                    self.add_permission_to_role(role_admin, pv)
        else:
            # Permissions on this view exist but....
            role_admin = self.find_role(self.auth_role_admin)
            for permission in base_permissions:
                # Check if base view permissions exist
                if not self.exist_permission_on_views(perm_views, permission):
                    pv = self.create_permission(permission, view_menu)
                    if self.auth_role_admin not in self.builtin_roles:
                        self.add_permission_to_role(role_admin, pv)
            for perm_view in perm_views:
                if perm_view.permission is None:
                    # Skip this perm_view, it has a null permission
                    continue
                if perm_view.permission.name not in base_permissions:
                    # perm to delete
                    roles = self.get_all_roles()
                    perm = self.get_action(perm_view.permission.name)
                    # del permission from all roles
                    for role in roles:
                        self.remove_permission_from_role(role, perm)
                    self.delete_permission(perm_view.permission.name, view_menu)
                elif (
                    self.auth_role_admin not in self.builtin_roles and perm_view not in role_admin.permissions
                ):
                    # Role Admin must have all permissions
                    self.add_permission_to_role(role_admin, perm_view)

    def add_permissions_menu(self, view_menu_name):
        """
        Adds menu_access to menu on permission_view_menu

        :param view_menu_name:
            The menu name
        """
        self.create_resource(view_menu_name)
        pv = self.get_permission("menu_access", view_menu_name)
        if not pv:
            pv = self.create_permission("menu_access", view_menu_name)
        if self.auth_role_admin not in self.builtin_roles:
            role_admin = self.find_role(self.auth_role_admin)
            self.add_permission_to_role(role_admin, pv)

    def security_cleanup(self, baseviews, menus):
        """
        Will cleanup all unused permissions from the database

        :param baseviews: A list of BaseViews class
        :param menus: Menu class
        """
        viewsmenus = self.get_all_resources()
        roles = self.get_all_roles()
        for viewmenu in viewsmenus:
            found = False
            for baseview in baseviews:
                if viewmenu.name == baseview.class_permission_name:
                    found = True
                    break
            if menus.find(viewmenu.name):
                found = True
            if not found:
                permissions = self.get_resource_permissions(viewmenu)
                for permission in permissions:
                    for role in roles:
                        self.remove_permission_from_role(role, permission)
                    self.delete_permission(permission.permission.name, viewmenu.name)
                self.delete_resource(viewmenu.name)

    def load_user(self, pk):
        return self.get_user_by_id(int(pk))

    def load_user_jwt(self, pk):
        user = self.load_user(pk)
        # Set flask g.user to JWT user, we can't do it on before request
        g.user = user
        return user

    @staticmethod
    def before_request():
        g.user = current_user
