# ldap-to-pg

Creates LDAP group members from specified OU in PostgreSQL.
Grants according roles in PG.

This program will search LDAP-groups with names starting with --group-prefix inside specified OU.
Then it will strip --group-prefix from each LDAP-group name and match that with according PG-role.
If no --group-prefix specified, then it will take all groups inside specified OU and will not strip anything from them.
All enabled members of these LDAP-groups will be created in postgres (PG-login-name=sAMAccountName).
PG-logins, whose matching LDAP-users are disabled or are not members of LDAP-groups inside specified OU anymore, will be dropped.
PG-roles will be granted/revoked to/from PG-logins according to LDAP-group membership.
PG-role "ldap" will be created (if not exists) and granted to all created logins. 

# compilation
To compile this script into single executable, first install prerequisites:
`sudo apt install libsasl2-dev python-dev libldap2-dev libssl-dev zlib1g-dev libpq-dev` (for Debian/Ubuntu)
`sudo yum install postgresql-devel python-devel openldap-devel zlib-devel` (For Centos/RedHat)
then install requirements.txt by running `pip3 install -r requirements.txt`, then run `pyinstaller --onefile ldap-to-pg.py`. It will create dist folder inside your current directory and place executable there.

# recipe

**Set up PG for LDAP-auth:**

- Add the following line in the beginning of pg_hba.conf and edit to suit your environment:
`host all +ldap 0.0.0.0/0 ldap ldapserver=ldap.sample.com ldapport=636 ldapscheme=ldap ldaptls=1 ldapbasedn="OU=Unit,DC=sample,DC=com" ldapbinddn="CN=ldap search,OU=Users,DC=sample,DC=com" ldapbindpasswd="P@$$w0rd" ldapsearchattribute="sAMAccountName"`

- In case of using self-signed AD certificate, you'll have to pass environment variable LDAPTLS_REQCERT=never to PostgreSQL. You can achieve this by adding a line `Environment="LDAPTLS_REQCERT=never"` to [Service] section of your patroni or postgresql unit-file. You can check, whether it was applied by running smth like this `cat /proc/<pid of postgres>/environ`

- Create all necessary groups inside PostgreSQL. I recommend creating read_all_data and write_all_data groups with according permissions in PG version <14. If PG version is 14+, then there already are roles named pg_read_all_data and pg_write_all_data. Keep treating those like read_all_data and write_all_data in AD-group naming. Synchronizer will automatically prepend pg_ in this case.

**Set up Active Directory**

- Create an OU to store your LDAP-groups
- Create necessary groups. I recommend using following naming scheme: servername_rolename, where servername is the name of your PG server or cluster and rolename - is the rolename in PostgreSQL.
Example: prodcl1_read_all_data, in this case you can launch program with --group-prefix prodcl1_ and all enabled members of this group will be created in PostgreSQL and granted read_all_data role (pg_read_all_data in case of PG14+). PG-group named "ldap" is always granted to these logins.

**Run ldap-to-pg synchronizer**

- At his point you can run ldap-to-pg. 
```
ldap-to-pg --group-prefix prodcl1_pg_ 
            --ou "OU=Postgres,OU=Groups,DC=sample,DC=com" 
            --ldap-host ldap.sample.com --ldap-port 636 --ldap-user ldapsearch@sample.com 
            --ldap-pwd P@$$W0rd --ldap-tls --pg-user postgres --pg-opts "connection limit 5" --log-level info --dry-run
```
- `--dry-run` option will just print the messages without changing anything. Remove --dry-run when there are no erros and you are ready.
