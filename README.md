Yii 1.1 HoneyPot / IP Checker
=============================
[![License](https://poser.pugx.org/foodette/yii1-honeypot/license)](https://packagist.org/packages/foodette/yii1-dotenv)

HoneyPot extension for Yii 1.1 Framework.

Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require --prefer-dist foodette/yii1-honeypot "*"
```

or add

```
"foodette/yii1-honeypot": "*"
```

to the require section of your `composer.json` file.

Usage
-----

Instantiate a `HttpBlackList` object with your `access key`
```php
use foodette\extension\yii1-honeypot

$httpBL = new HttpBlackList('youraccesskey');
```

### Check an IP address

The `check` method will return a boolean indicating wether the IP address is known to have suspicious activity.

```
$httpBL->check('1.2.3.4');
// returns true|false
```

### Query an IP address

The `query` method will return an array with details about suspicious activity

```
$httpBL->check('1.2.3.4');
```
    returns [] when IP is ok
    returns [
        'lastActivity'  => 12 // number of days since last activity 
        'threatScore'   => 39 // threat score on a 0-100 scale
        'type'          => 1  // visitor type bit, e.g. Suspicious|Harvester|Comment spam
    ]

See [the Project Honey Pot API](https://www.projecthoneypot.org/httpbl_api.php) for more information.
