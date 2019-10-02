# Active Directory Bundle

- [Installation](#using-the-configuration)
- [Configuration](#configuration)
- [Definitions](#definitions)
    - [Account Suffix (required)](#account-suffix-required)
    - [Domain Controllers (required)](#domain-controllers-required)
    - [Base Distinguished Name (required)](#base-distinguished-name-required)

Configuring Active Directory Bundle is really easy. Let's get started.

## Installation

Install using composer:

```bash
composer config repositories.repo-name vcs ssh://git@gitlab.com:22/xrow-shared/activedirectory-bundle.git
composer require xrow/activedirectory-bundle
```

Add to `$bundles` array in `app/AppKernel.php`:

```php
            new Xrow\ActiveDirectoryBundle\XrowActiveDirectoryBundle(),
```

## Configuration

You can configure Active Directory Bundle by supplying an array of settings. Keep in mind not all of these are required. This will be discussed below.

Here is an example configuration (for example in `app/config.yml`) with all possible configuration options:

```yaml
xrow_active_directory:
    account_suffix: xrow.lan
    domain_controllers: [ "dc01.xrow.lan","192.168.0.220"]
    base_dn: "dc=XROW,dc=LAN"
```

## Working with Active Directory user groups

Once the a new active directory did try to authenticate against ezplatform. All of the user groups are available from the cms backend. You can now assign (Admin Panel->Roles) the eZ Platform security policy Administrator to the Active Directory group Administrators (Admin Panel->Users->Administators). Beware the only difference between eZ Platform user groups and Active Directory user groups is a special remote_id that is not visible from the cms backend. Deleted Active Directory items will appear again once a user authenticates again with the platform.

## Definitions

### Account Suffix (required)

The account suffix option is the suffix of your user accounts in AD. For example, if your domain DN is `DC=corp,DC=acme,DC=org`,
then your account suffix would be `corp.acme.org`. This is then appended to the end of your user accounts on authentication.

For example, if you're binding as a user, and your username is `jdoe`, then Adldap would try to authenticate with
your server as `jdoe@corp.acme.org`.

### Domain Controllers (required)

The domain controllers option is an array of servers located on your network that serve Active Directory. You insert as many
servers or as few as you'd like depending on your forest (with the minimum of one of course).

For example, if the server name that hosts AD on my network is named `ACME-DC01`, then I would insert `['ACME-DC01.corp.acme.org']`
inside the domain controllers option array.

### Base Distinguished Name (required)

The base distinguished name is the base distinguished name you'd like to perform operations on. An example base DN would be `DC=corp,DC=acme,DC=org`.

If one is not defined, you will not retrieve any search results.

## Toubleshooting

### System report "Invalid directory user" during login

Certain Active Directory users might be not able to authenticate against the Active Directory Server. In those cases the message "Invalid directory user" will appear. This means that the user username@account.suffix with the given password can`t authenticate against teh server. Please consult the domain adminsitrator to help. You can replicate the issue using a LDAP browser like [LDAP Admin](http://www.ldapadmin.org).

### Need of adding a second Active Directory

In case you need to add a second active directory structure we recommend you to build a [forest](https://en.wikipedia.org/wiki/Active_Directory#Forests,_trees_and_domains).
