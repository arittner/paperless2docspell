# paperless2docspell
Migrates Paperless NG documents to Docspell

This is a very simple (not finished) phython script to transfer paperless documents to a docspell server. 

The scipt is highly configurable and needs a config.json script to map the paperless-ng tags to the docspell attributes. Docspell supports more meta information than paperless-ng and the scipt transforms specific data to the docspell attributes.

## Configuration

The configuration file allows a lot of transformation definitions. In paperless-ng the document-type can be transformed to a tag with a specific category. Otherwise tags from paperless-ng can be transformed to persons, organizations and equipment. Docspell supports mor attributes for correspondents and this scipt creates the data for you.

You don't need to store the passwords in the config.json file. In this case, the script ask for the passwords.

**Example**

```json
{
    "limit": 5,
    "page-size": 20,
    "update-existing": false,

    "docspell": {
        "url": "http://127.0.0.1:7880/",
        "username": "docspellusername",
        "password": "secret!",
        "doc-type": {
            "import": "tag",
            "name": "Dokumenttyp"
        },
        "tags": {
            "category": null,
            "concerns": {
                "mapping": [
                    {"Alice": "Alicia Keys"},
                    {"Bob": "Bobby Tale"}
                ],
                "default": {
                    "street": "",
                    "zip": "99999",
                    "city": "Somewhere",
                    "country": "DE"
                }
            },
            "equipment": {
                "mapping": [
                    {"Mower": "Lawn mower"}
                ],
                "default": {
                    "use": "concerning",
                    "note": null
                }
            }
        },
        "correspondents": {
            "mapping": [
                {"Peter": {"name": "Peter Pan", "create-as": "person"}},
                {"Paul":  {"name": "Paul Panther", "create-as": "person"}}
            ],
            "default": {
                "create-as": "organization"
            }
        }
    },
    "paperless-ng": {
        "url": "http://localhost:8931/",
        "username": "paperlessusername",
        "password": "secret?",
        "classification-limit": 9999
    }
}
```

**Explanation**

*General config*

```json
{
    "limit": 5,
    "page-size": 20,
    "update-existing": false
}
```

* **limit** defines the maximum amount of documents to import. 
* **page-size** page size to fetch a bulk from paperless-ng
* **update-existing** if true, existing documents will be updated


*Paperless-NG*

```json
{
    "paperless-ng": {
        "url": "http://localhost:8931/",
        "username": "paperlessusername",
        "password": "secret?",
        "classification-limit": 9999
    }
}
```

* **paperless-ng.url** URL to paperless-ng
* **paperless-ng.username** Username to access the endpoints
* **paperless-ng.password** Password to authenticate
* **paperless-ng.classification-limit** maximum number of classifications to import


*Docspell - general config*

```json
{
    "docspell": {
        "url": "http://127.0.0.1:7880/",
        "username": "docspellusername",
        "password": "secret!"
    }
}
```

* **docspell.url** URL to docspell
* **docspell.username** Username to access the endpoints
* **docspell.password** Password to authenticate


*Docspell - paperless-ng doctype mapping*

```json
{
    "docspell": {
        "doc-type": {
            "import": "tag",
            "name": "Dokumenttyp"
        }
    }
}
```

Paperless-ng supports document types but not Docspell. This configuration transforms the document type from paperless-ng to another attribute in docspell. Currently only `tag` is implemented.

* **docspell-ng.doc-type.import** should be `tag`
* **docspell-ng.doc-type.name** The catgory-name of the tag in docspell


*Docspell - paperless-ng tags mapping - general*

```json
{
    "docspell": {
        "tags": {
            "category": null
        }
    }
}
```

* **docspell.tags.category** should have a name and defiunes the category-name for all imported tags from paperless-ng


*Docspell - paperless-ng tags mapping to concerns*

```json
{
    "docspell": {
        "tags": {
            "concerns": {
                "mapping": [
                    {"Alice": "Alicia Keys"},
                    {"Bob": "Bobby Tale"}
                ],
                "default": {
                    "street": "",
                    "zip": "99999",
                    "city": "Somewhere",
                    "country": "DE"
                }
            }
        }
    }
}
```

Maps the tags from paperless-ng to concerns (as persons). Because paperless-ng does not support concerning persons, the script can map tags with a specific name to a person record in docspell and link the document.


* **docspell.tags.concerns.mapping.?** 
  - A list of Key / Value mappings. The key is the corresponding tag in paperless-ng, the value is used to create a person record in docspell

* **docspell.tags.concerns.default.?** 
  - The default address record information to create the persons


*Docspell - paperless-ng tags mapping to equipment*

```json
{
    "docspell": {
        "tags": {
            "equipment": {
                "mapping": [
                    {"Mower": "Lawn mower"}
                ],
                "default": {
                    "use": "concerning",
                    "note": null
                }
            }
        }
    }
}
```

Maps the tags from paperless-ng to equipment. Because paperless-ng does not support equipments, the script can map tags with a specific name to an equipment record in docspell and link the document.

* **docspell.tags.equipment.mapping.?** 
  - A list of Key / Value mappings. The key is the corresponding tag in paperless-ng, the value is used to create an equipment record in docspell

* **docspell.tags.equipment.default.?** 
  - The default equipment information to create the equipment record


*Docspell - paperless-ng correspondents mapping*

```json
{
    "docspell": {
        "correspondents": {
            "mapping": [
                {"Peter": {"name": "Peter Pan", "create-as": "person"}},
                {"Paul":  {"name": "Paul Panther", "create-as": "person"}}
            ],
            "default": {
                "create-as": "organization"
            }
        }
    }
}
```

Maps the paperless-ng correspondents to docspell correspondents. Paperless-ng supports only names and docspell is able to distinguish between `person` and `organization`. 

* **docspell.correspondents.mapping.?** 
  - Maps the `Key` (the paperlessng correspondent name) to the docspell record. With "create-as" the record type can be `person` or `organization`

* **docspell.correspondents.default.create-as** should be `person` or `organization`
