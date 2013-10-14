httpauth
========
A filter implementing [HTTP basic auth](http://en.wikipedia.org/wiki/Basic_access_authentication), protecting single API
endpoints, specific actions and controllers or even entire applications.

Installation
============
Copy `HttpAuthFilter` into your `component` directory.

Usage
=====
Modify the controller you wish to protect in a way that the `filters()` method starts of like this:
```
public function filters()
{
    return array(
        array(
            'HttpAuthFilter',
        )
        ...
    );
}
```
Make sure the filter is the first in the list and does not cover actions that should be reachable by unauthenticated
users (which were just cruel).