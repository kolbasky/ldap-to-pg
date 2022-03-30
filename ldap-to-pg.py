#!/usr/bin/env python3
import traceback
import sys
import logging
import re
import time
import argparse

import ldap
import psycopg2


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description = """example: {} --group-prefix prodcl1_pg_ 
            --ou "OU=Postgres,OU=Groups,DC=sample,DC=com" 
            --ldap-host ldap.sample.com --ldap-port 636 --ldap-user ldapsearch@sample.com 
            --ldap-pwd P@$$w0rd --ldap-tls --pg-user postgres --pg-opts "connection limit 5" --log-level info
            """.format(sys.argv[0]),
        epilog = """This program will search LDAP-groups with names starting with --group-prefix inside specified OU.
            Then it will strip --group-prefix from each LDAP-group name and match that with according PG-role.
            If no --group-prefix is specified, then all groups inside OU are taken, and nothing is stripped from their names.
            All enabled members of these LDAP-groups will be created in postgres (PG-login=sAMAccountName).
            PG-logins, whose matching LDAP-users are disabled 
            or are not members of LDAP-groups inside specified OU anymore, will be dropped.
            PG-roles will be granted/revoked to/from PG-logins according to LDAP-group membership.
            PG-role "ldap" will be created (if not exists) and granted to all created logins. 
            To use LDAP authentication in postgres enable it by adding a line in the beginning of pg_hba.conf:

            host all +ldap 0.0.0.0/0 ldap ldapserver=ldap.sample.com ldapport=636 ldapscheme=ldap 
            ldaptls=1 ldapbasedn="OU=Unit,DC=sample,DC=com" 
            ldapbinddn="CN=ldap search,OU=Users,DC=sample,DC=com" 
            ldapbindpasswd="P@$$w0rd" ldapsearchattribute="sAMAccountName\"
            """,
        prog = sys.argv[0]
    )
    parser.add_argument('-g', '--group-prefix', type = str, default = "",
                        help = """Prefix, used to search groups in OU. 
                            (i.e. name of this server or cluster) (default: empty)
                        """
    )
    parser.add_argument('-o', '--ou', type = str, required = True,
                        help = """DN of OU in LDAP to search groups in"""
    )
    parser.add_argument('-s', '--ldap-host', type = str, required = True,
                        help = """LDAP hostname or ip address"""
    )
    parser.add_argument('-p', '--ldap-port', type = int, default = 389,
                        help = """LDAP port (default: 389)"""
    )
    parser.add_argument('-u', '--ldap-user', type = str, required = True,
                        help = """LDAP user in user@domain.com format"""
    )
    parser.add_argument('-w', '--ldap-pwd', type = str, required = True,
                        help = """LDAP password"""
    )
    parser.add_argument('-t', '--ldap-tls', default = False, action = 'store_true',
                        help = """Use TLS when connecting to ldap (default: False)"""
    )
    parser.add_argument('-c', '--ldap-tls-check', default = False, action = 'store_true',
                        help = """Don’t check LDAP cert and host name. 
                            Does not affect encryption. (default: False)
                        """
    )
    parser.add_argument('-S', '--pg-host', type = str, default = 'localhost',
                        help = """PostgreSQL hostname or ip address (default: localhost)"""
    )
    parser.add_argument('-P', '--pg-port', type = int, default = 5432,
                        help = """PostgreSQL port (default: 5432)"""
    )
    parser.add_argument('-D', '--pg-db', type = str, default = 'postgres',
                        help = """PostgreSQL database (default: postgres)"""
    )
    parser.add_argument('-U', '--pg-user', type = str,
                        help = """PostgreSQL user (default: current user)"""
    )
    parser.add_argument('-W', '--pg-pwd', type = str,
                        help = """PostgreSQL password. If not specified 
                            .pgpass is used or trust rule is needed in pg_hba.conf (default: empty)
                        """
    )
    parser.add_argument('-O', '--pg-opts', type = str,
                        help = """Parameters for PG-login creation. This string will be
                            appended to the "CREATE ROLE name LOGIN" statement (default: empty)
                            (example: "connection limit 5 createdb")
                        """
    )
    parser.add_argument('-d', '--dry-run', default = False, action = 'store_true',
                        help = """Dry run. Don\'t execute any SQL-commands (default: False)"""
    )
    parser.add_argument('-l', '--log-level', type = str, default = 'WARNING',
                        help = """Logging level (default: warning)"""
    )
    parser.add_argument('-V', '--version', 
                    action='version',                    
                    version='ldap-to-pg version 1.0'
    )
    cli_vars = parser.parse_args()
    return(cli_vars)


def ldap_auth(address, username, password, tls, tls_check):
    try:
        if not tls_check:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        conn = ldap.initialize('ldap://' + address)
        conn.protocol_version = 3
        conn.set_option(ldap.OPT_REFERRALS, 0)
        if tls:
            conn.start_tls_s()
        conn.simple_bind_s(username, password)
        logging.info ("Successfully connected to LDAP Server")
    except Exception as error:
        logging.error ("Error connectiong to LDAP: {}".format(error))
        logging.error ("Synchronization failed!")
        sys.exit(-1)
    return conn


def get_sam_by_dn(dn, status, ad_conn):
    logging.debug('Searching in LDAP for following DN: ' + dn.decode('utf-8'))
    try:
        sam = ''
        uac = ''
        if status == 'enabled':
            result = ad_conn.search_s(
                dn.decode('utf-8'), 
                ldap.SCOPE_BASE, 
                '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
            )
        elif status == 'disabled':
            result = ad_conn.search_s(
                dn.decode('utf-8'),
                ldap.SCOPE_BASE,
                '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
            )
        else:
            result = ad_conn.search_s(
                dn.decode('utf-8'),
                ldap.SCOPE_BASE,
                '(&(objectCategory=person)(objectClass=user))'
            )
        logging.debug('Found DN: ' + str(result[0][0]))
        if result:
            for dn, attrb in result:
                if 'sAMAccountName' in attrb and attrb['sAMAccountName']:
                    sam = attrb['sAMAccountName'][0].lower()
                    break
            for dn, attrb in result:
                if 'userAccountControl' in attrb and attrb['userAccountControl']:
                    uac = "enabled" if int(bin(int(attrb['userAccountControl'][0]))[2:]) & 1 << 1 == 0 else 'disabled'
                    break
    except Exception as error:
        logging.error ("Error querying sAMAccountName for {} in LDAP: {}".format(dn, error))
        logging.error ("Synchronization failed!")
        sys.exit(-1)
    return sam, uac


def get_ou_groups(ad_conn, group_prefix, ou):
    try:
        members = []
        ad_filter = '(&(objectClass=GROUP)(cn=*))'
        result = ad_conn.search_s(ou, ldap.SCOPE_SUBTREE, ad_filter, ['cn'])
        if len(result[0]) >= 2:
            for m in result:
                if group_prefix and re.search(
                        '({group_prefix})'.format(
                            group_prefix = group_prefix),
                        m[1]['cn'][0].decode('utf-8')):
                    members.append(m[1]['cn'][0].decode('utf-8'))
                if not group_prefix:
                    members.append(m[1]['cn'][0].decode('utf-8'))
    except Exception as error:
        logging.error ("Error querying {} members in LDAP: {}".format(ou, traceback))
        logging.error ("Synchronization failed!")
        sys.exit(-1)
    if group_prefix:
        logging.info('Filtered OU members: ' + str(members))
    else:
        logging.info('All OU members: ' + str(members))
    return members


def get_group_members(group_name, status, ad_conn):
    basedn = ""
    for s in cli_vars.ou.split(','):
        if "DC=" in s:
            basedn += "{},".format(s)
    basedn = basedn[:-1]
    if len(basedn) < 4:
        logging.error ("Error parsing OU to find out basedn. Is there \"DC=\" part on the right?")
        logging.error ("Synchronization failed!")
        sys.exit(-1)
    try:
        members = []
        ad_filter = '(&(objectClass=GROUP)(cn={group_name}))'.replace('{group_name}', group_name)
        result = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)
        if result:
            if len(result[0]) >= 2 and 'member' in result[0][1]:
                members_tmp = result[0][1]['member']
                for m in members_tmp:
                    sam, uac = get_sam_by_dn(m, status, ad_conn)
                    if sam and uac:
                        members.append([sam.decode('utf-8'), uac])
    except Exception as error:
        logging.error ("Error querying {} members in LDAP: {}".format(group_name, error))
        logging.error ("Synchronization failed!")
        sys.exit(-1)
    logging.info('{status} members of LDAP-group {group_name}: '.format(
        group_name = group_name,
        status = status) 
        + str(members)
    )
    return members


def pg_auth(host = 'localhost', port = '5432', dbname = 'postgres', user = '', password = ''):
    connstring = "host='{host}' port='{port}' dbname='{dbname}'".format(
        host = host,
        port = port,
        dbname = dbname
    )
    if user: connstring += ' user={user}'.format(user = user)
    if password: connstring += ' password={password}'.format(password = password)
    try:
        conn = psycopg2.connect(connstring)
        conn.autocommit = True
        logging.info ("Successfully connected to PostgreSQL Server")
    except Exception as error:
        logging.error("Connection to PostgreSQL Server failed. {traceback}".format(
            traceback = traceback.format_exc())
        )
        logging.error ("Synchronization failed!")
        sys.exit(-1)
    return conn


def get_pg_version(conn):
    cur = conn.cursor()
    query = """SELECT FLOOR(SUBSTRING(CURRENT_SETTING('server_version') 
        FROM '\d*\.\d*')::NUMERIC(6,2))::INT;
    """
    try:
        cur.execute(query)
        result = cur.fetchall()
        logging.info('PostgreSQL major version is: ' + str(result[0][0]))
    except Exception as error:
        logging.error("Query execution failed. {traceback}".format(
            traceback = traceback.format_exc())
        )
        logging.error ("Synchronization failed!")
        sys.exit(-1)
    return result[0][0]


def print_pg_notices(conn):
    for notice in conn.notices:
        if "INFO:" in notice:
            logging.info(notice[:-1].split(': ')[1].strip())
        else:
            logging.warning(notice[:-1].split(': ')[1].strip())


def ad_to_pg_groupname(group_name, group_prefix, pg_version):
    # Ad groups look like testpg13vip1_pg_all_data_reader
    # Postgresql groups look like all_data_reader when pg version < 14
    # If version >= 14, then prepend pg_ to all_data_reader and all_data_writer
    if group_prefix:
        group = group_name.split(group_prefix)
        group = group[1]
    else:
        group = group_name
    if pg_version >= 14 and ('read_all_data' in group or 'write_all_data' in group):
        group = 'pg_{}'.format(group)
    logging.debug('LDAP-to-PG group mapping: ' + group_name + ' -> ' + group)
    return group


def sync_pg_logins(ou, ad_conn, pg_conn, group_prefix, pg_login_options, dry_run):
    conn = pg_conn
    with conn.cursor() as cur:
        # Check pg is in recovery
        query = "select pg_is_in_recovery();"
        logging.debug('Query:\n' + query)
        cur.execute(query)
        result = cur.fetchall()
        if result[0][0]:
            logging.warning('Postgres is in recovery! Nothing to do..')
            sys.exit(0)        
    pg_version = get_pg_version(pg_conn)
    group_names = get_ou_groups(ad_conn, group_prefix, ou)
    groups_members_dict = {}
    all_enabled_members, all_disabled_members = '', ''
    for group in group_names:
        groups_members_dict[group] = get_group_members(group, 'All', ad_conn)
    for k, v in groups_members_dict.items():
        for l in v:
            if l[1] == 'enabled' and l[0] not in all_enabled_members:
                all_enabled_members+="'" + l[0] + "',"
            if l[1] == 'disabled' and l[0] not in all_disabled_members:
                all_disabled_members += "'" + l[0] + "',"
    all_enabled_members = all_enabled_members[:-1]
    all_disabled_members = all_disabled_members[:-1]
    if not all_enabled_members: all_enabled_members = "''"
    if not all_disabled_members: all_disabled_members = "''"
    conn = pg_conn
    with conn.cursor() as cur:
        # Check for ldap group existance 
        query = """DO
$DO$
begin
    if not exists (select 1 from pg_roles where rolname = 'ldap') then
        begin
            if not {dry_run} then
                create role ldap;
            end if;
            raise warning 'ldap group has been created';
        end;
    end if;
end
$DO$
"""     
        logging.debug('Query (Check for ldap group existance):\n' + query.format(dry_run = dry_run))
        cur.execute(
            query.format(dry_run = dry_run)
        )
        # Drop logins disabled in ad and logins, who are not members of any ad-group in OU any more
        query = """DO
$do$
    declare
        _login text;
        _logins_to_drop text[] := (select array_agg(distinct l.rolname)::text[]
                from pg_roles l
                    join pg_auth_members am
                        on l.oid = am.member
                    join pg_roles r
                        on r.oid = am.roleid
                    where
                            (r.rolname = 'ldap'
                            and l.rolname not in ({all_enabled_members}))
                        or
                            l.rolname in ({all_disabled_members})
            );
    begin
        if array_length(_logins_to_drop,1) is NOT NULL then
            foreach _login in array _logins_to_drop
            loop
                if not {dry_run} then
                    execute format ('select pg_terminate_backend(pid) from pg_stat_activity where usename = ''%I''', quote_ident(_login));
                    execute format('drop role %I', quote_ident(_login));
                end if;
                raise notice 'Dropped login %', _login;
            end loop;
        else
            raise info 'No logins to drop';
        end if;
    end
$do$;
        """
        logging.debug('Query (Drop logins disabled in ad and logins, who are not members of any ad-group in OU any more):\n' + query.format(
                        all_enabled_members = all_enabled_members,
                        all_disabled_members = all_disabled_members,
                        dry_run = dry_run)
                    )
        cur.execute(
            query.format(
                        all_enabled_members = all_enabled_members,
                        all_disabled_members = all_disabled_members,
                        dry_run = dry_run
                    )
        )

        # Revoke role membership in pg from those logins, who are not members of according ad-group
        for group in groups_members_dict:
            enabled_members, disabled_members = '',''
            for m in groups_members_dict[group]:
                if m[1] == 'enabled' and m[0] not in enabled_members:
                    enabled_members+="'" + m[0] + "',"
                if m[1] == 'disabled' and m[0] not in disabled_members:
                    disabled_members += "'" + m[0] + "',"
            enabled_members = enabled_members[:-1]
            disabled_members = disabled_members[:-1]
            if not enabled_members: enabled_members = "''"
            if not disabled_members: disabled_members = "''"
            pg_group = ad_to_pg_groupname(group, group_prefix, pg_version)
            query = """DO
$do$
    declare
        _logins_to_revoke text[];
        _login text;
    begin
        if '{pg_group}' like '%superuser%' then
            _logins_to_revoke := (select array_agg(l.rolname)::text[]
                                    from pg_roles r left join pg_auth_members am on r.oid=am.roleid
                                    left join pg_roles l on l.oid=am.member
                                    where r.rolname='ldap' and l.rolname not in ({enabled_members}) and l.rolsuper);
        else
            _logins_to_revoke := (select array_agg(l.rolname)::text[]
                    from pg_roles r left join pg_auth_members am on r.oid=am.roleid
                    left join pg_roles l on l.oid=am.member
                    where r.rolname='{pg_group}' and l.rolname not in ({enabled_members}));
        end if;

        if array_length(_logins_to_revoke,1) is not NULL then
            if '{pg_group}' like '%superuser%' then
                foreach _login in array _logins_to_revoke
                loop
                    if not {dry_run} then
                        execute format('alter role %I with nosuperuser', quote_ident(_login));
                    end if;
                    raise notice 'Revoked {pg_group} from %', _login;
                end loop;
            else
                foreach _login in array _logins_to_revoke
                loop
                    if not {dry_run} then
                        execute format('revoke %I from %I', '{pg_group}', quote_ident(_login));
                    end if;
                    raise notice 'Revoked {pg_group} from %', _login;
                end loop;
            end if;
        else
            raise info 'No logins to revoke {pg_group} from';
        end if;
    end
$do$
            """
            logging.debug('Query (Revoke role membership in pg from those logins, who are not members of according ad-group):\n' + query.format(
                            pg_group = pg_group,
                            enabled_members = enabled_members,
                            dry_run = dry_run
                        ))
            cur.execute(
                query.format(
                            pg_group = pg_group,
                            enabled_members = enabled_members,
                            dry_run = dry_run
                        )
            )

        # Create logins from ad-group, grant according pg-roles
        for group in groups_members_dict:
            enabled_members = []
            for m in groups_members_dict[group]:
                if m[1] == 'enabled' and m[0] not in enabled_members:
                    enabled_members.append(m[0])
            pg_group = ad_to_pg_groupname(group, group_prefix, pg_version)
            for login in enabled_members:
                query = """DO
$do$
    begin
        if not exists (
            select from pg_catalog.pg_roles
            where  rolname = '{login}') then
            if not {dry_run} then
                create role {login} login {pg_login_options};
            end if;
            raise notice 'Created login {login} {pg_login_options}';
            if '{pg_group}' like '%superuser%' then
                if not {dry_run} then
                    alter role {login} with superuser;
                end if;
                raise notice 'Granted role {pg_group} to {login}';
            else
                if not {dry_run} then
                    grant {pg_group} to {login};
                end if;
                raise notice 'Granted role {pg_group} to {login}';
            end if;
            if not {dry_run} then
                grant ldap to {login};
            end if;
        else
            if '{pg_group}' like '%superuser%' then
                if not exists (select 1 from pg_roles
                                    where rolname = '{login}' and rolsuper) then
                    if not {dry_run} then
                        alter role {login} with superuser;
                    end if;
                    raise notice 'Granted role {pg_group} to {login}';
                else
                    raise info '{login} is already a superuser';
                end if;
            else
                if not exists (select 1
                            from pg_roles l
                                join pg_auth_members am
                                    on l.oid = am.member
                                join pg_roles r
                                    on r.oid = am.roleid
                                where   r.rolname = '{pg_group}' and l.rolname = '{login}') then
                    if not {dry_run} then
                        grant {pg_group} to {login};
                    end if;
                    raise notice 'Granted role {pg_group} to {login}';
                else
                    raise info '{login} is already a member of {pg_group}';
                end if;
            end if;
        end if;
        if not exists (select 1
            from pg_roles l
                join pg_auth_members am
                    on l.oid = am.member
                join pg_roles r
                    on r.oid = am.roleid
                where   r.rolname = 'ldap' and l.rolname = '{login}') then
            if not {dry_run} then
                grant ldap to {login};
            end if;
            raise warning 'Granted role "ldap" to {login}';
        else
            raise info '{login} is already a member of "ldap" group';
        end if;
    end
$do$
                """
                logging.debug('Query (Create logins from ad-group, grant according pg-roles):\n' + query.format(
                                login = login,
                                pg_group = pg_group,
                                pg_login_options = pg_login_options,
                                dry_run = dry_run)
                )
                cur.execute(
                    query.format(
                                login = login,
                                pg_group = pg_group,
                                pg_login_options = pg_login_options,
                                dry_run = dry_run)
                )


if __name__ == "__main__":
    cli_vars = parse_cli_args()
    logging.basicConfig(format = '%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
                        datefmt = '%d/%m/%Y %H:%M:%S',
                        level = cli_vars.log_level.upper()
    )
    if not cli_vars.dry_run:
        logging.warning("Synchronization started!")
    else:
        logging.warning("Synchronization started in dry_run mode!")
        logging.warning("All further messages reflect what would happen. \
No actual changes are made!"
        )
    parms = ""
    for arg in vars(cli_vars): parms += ('\t' 
        + str(arg) 
        + ' = ' 
        +  str(getattr(cli_vars, arg)) 
        + '\n'
    )
    parms = parms[:-1]
    logging.info('Program is started with following parameters:\n' + parms)
    ad_uri = cli_vars.ldap_host + ':' + str(cli_vars.ldap_port)
    ad_conn = ldap_auth(
        address = ad_uri,
        username = cli_vars.ldap_user,
        password = cli_vars.ldap_pwd,
        tls = cli_vars.ldap_tls,
        tls_check = cli_vars.ldap_tls_check
    )
    pg_conn = pg_auth(
        host = cli_vars.pg_host,
        port = cli_vars.pg_port,
        dbname = cli_vars.pg_db,
        user = cli_vars.pg_user,
        password = cli_vars.pg_pwd
    )
    with pg_conn:
        try:
            pg_login_opts= "" if not cli_vars.pg_opts else cli_vars.pg_opts
            sync_pg_logins(
                cli_vars.ou,
                ad_conn,
                pg_conn,
                cli_vars.group_prefix,
                pg_login_opts,
                dry_run = cli_vars.dry_run
            )
            ad_conn.unbind()
            print_pg_notices(pg_conn)
        except Exception as error:
                    print_pg_notices(pg_conn)
                    logging.error ('Error: {traceback}'.format(
                        traceback = traceback.format_exc())
                    )
                    logging.error ("Synchronization failed!")
                    sys.exit(-1)
    if not cli_vars.dry_run:
        logging.warning("Synchronized successfully at {}".format(
            str(int(time.time())))
        )
    else:
        logging.warning("Dry run of synchronization finished successfully")
    sys.exit(0)