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
