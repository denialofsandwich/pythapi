# pythapi
A flexible and light API for nearly every purpose with focus on extensibility.

This Project is designed to easily create your own webservices and connect it with others. Nearly everything is running as a plugin, which means that you can easily extend and remove features if needed.

## Install

The following Packages are required to run pythapi:

Core:
* python
* python-tornado
* python-mysqldb
* python-configparser

Authentification Plugin:
* python-crypto

You can install them on Debian with the following command:

`apt-get install python python-tornado python-mysqldb python-configparser python-crypto`

To install pythapi, clone this project in your desired directory:

`git clone https://github.com/denialofsandwich/pythapi.git`

Create a database user (example in bash):

```bash
MYSQL_ROOTPW="yourpasswordhere"
PYTHAPI_DB_NAME="pythapi"
PYTHAPI_DB_USER="pythapi"
PYTHAPI_DB_PASSWORD="changeme"

mysql -p$MYSQL_ROOTPW <<EOM
DROP DATABASE IF EXISTS $PYTHAPI_DB_NAME;
DROP USER IF EXISTS '$PYTHAPI_DB_USER'@'localhost';
CREATE DATABASE $PYTHAPI_DB_NAME;
CREATE USER '$PYTHAPI_DB_USER'@'localhost' IDENTIFIED BY '$PYTHAPI_DB_PASSWORD';
GRANT ALL PRIVILEGES ON $PYTHAPI_DB_NAME.* TO '$PYTHAPI_DB_USER'@'localhost';
EOM
```

Navigate to your pythapi directory and copy `pythapi.example.ini` to `pythapi.ini.`
Change the the nessesary parameters.

**IMPORTANT**: generate a salt. This dramaticaly increases the security. You can do this in linux with:

`</dev/urandom tr -dc A-Za-z0-9 | head -c 64`

At last you need to install all installed plugins.

`./pythapi.py install`

You can get more information about the parameters with

`./pythapi.py --help`

Now you can start pythapi with the command `./pythapi.py`

If everything is running fine, you can get a list of all running plugins and its possible requests with:

**NOTE**: This example uses `jq` to format the returned JSON Object and `curl` to make a request. You can install it on Debian with the following command:

`apt-get install curl jq`

```bash
# List all plugins
curl -X GET http://localhost:8123/info/list | jq

# Get all available requests of a plugin
curl -X GET http://localhost:8123/info/<plugin_name>/list | jq
```

This project is currently in early alpha state. Even the readme is not finished yet.
