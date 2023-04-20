# Marina Dockyard RESTful API

Allows for management of a marina dockyard containing users, boats and cargo load entities via RESTful API calls. Hosted on Google Cloud via App Engine utilizing Google NoSQL Cloud Datastore.


## Technologies

* Google Cloud App Engine
* Google NoSQL Cloud Datastore
* Postman Tests
* Python (Flask)
* OAuth 2.0
* JWT

## Use Cases / User Stories

* Users can create an account and authenticate with Auth0.
* Users can view boats view their boats and the cargo loads on them.
* Users can create, update, or delete only boats belonging to them.
* Users can add or remove cargo loads only from the boats they own.
* Users can create or delete cargo loads that are on land or on their boats.
* We can ensure boats can only have one owner and that cargo loads can only be on one boat at a time.
* Only authenticated users with a valid JWT can access protected boat entities.
* We will assume cargo loads are an unprotected resource and can be created or deleted at any time.
* We can ensure that users are the owner of a boat before they can add or remove cargo loads from it.
* We can ensure that the capacity of the boat is checked before creating new cargo loads, and that new cargo loads are only created if the current number of cargo loads on the boat does not exceed the capacity.
