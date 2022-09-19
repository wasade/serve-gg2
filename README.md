# Greengenes2 web server

Welcome to the Greengenes2 web server project! The scope of this repository is to provide a user experience for interacting with and exploring the data covered by Greengenes2. 

The code in this repository is responsible for:

* Serving a single webpage to users
* Performing lookups against a SQLite3 database

The construction of the database is handled by the [q2-greengenes2](https://github.com/wasade/q2-greengenes2) project. 

# Design

The single webpage served to users was designed to operate responsively to JSON retrieved from the SQLite3 database. Specifically, a templated HTML page is formatted with the JSON object, creating a Javascript variable that holds the data to display. Javascript then examines the object to determine what structures and content to display to the user.

The approach taken here was pragmatic as the number of types of pages to present was relatively small. This also pushes processing client side, alleviating (minor) burden from the webserver. 
