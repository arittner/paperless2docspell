# Copyright 2022 - Aljoscha Rittner
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import datetime
import hashlib
import os
import time
import urllib.parse
import urllib.request
import urllib.response
import json
import getpass
import cgi
import tempfile
import functools
import mimetypes
import uuid
import io


# ########################
# config
##########################
def load_config() -> json:
    """
    Loads the configuration from config.json
    """
    with open("config.json", 'r', encoding="utf-8") as stream:
        config = json.load(stream)

        if "docspell" not in config:
            raise ValueError("'docspell' config is missing")
        if "paperless-ng" not in config:
            raise ValueError("'paperless-ng' config is missing")

        if "password" not in config["docspell"]:
            config["docspell"]["password"] = getpass.getpass(
                f"DocSpell password for '{config['docspell']['username']}':")
        if "password" not in config["paperless-ng"]:
            config["paperless-ng"]["password"] = getpass.getpass(
                f"Paperless-NG password for '{config['paperless-ng']['username']}':")

        return config


def deep_get(dictionary: dict, keys: str, default=None):
    """
    Helper method to access a dictionary value.

    :param dictionary: The dictionary with the structured configuration data
    :param keys: A key-path with dot-separator like "path.to.key"
    :param default: The default if the key path dos not exists.

    :returns: Found value for the key-path or 'default'
    """
    return functools.reduce(
        lambda d, key: d.get(key, default) if isinstance(d, dict) else default, keys.split("."), dictionary)


# ########################
# paperless-ng
##########################


def pl_get_filename(opener: urllib.request.OpenerDirector, doc_id: str) -> str:
    """
    Extracts the file name from a download.

    :param opener: open director with credentials
    :param doc_id: document it
    :return: file name
    """
    url = ''.join([pl_top_level_url, "api/documents/", doc_id, "/download/"])
    with contextlib.closing(opener.open(url)) as remote_file:
        content_disp = remote_file.info()["Content-Disposition"]
        value, params = cgi.parse_header(content_disp)
        return params["filename"]


def pl_download_document(opener: urllib.request.OpenerDirector, doc_id: str) -> (str, str):
    """
    Downloads a document from paperless-ng.

    :param opener: open director with credentials
    :param doc_id: document id
    :return: path to downloaded binary, original name
    """
    url = ''.join([pl_top_level_url, "api/documents/", str(doc_id), "/download/"])
    with contextlib.closing(opener.open(url)) as remote_file:
        content_disp = remote_file.info()["Content-Disposition"]
        value, params = cgi.parse_header(content_disp)

        with tempfile.NamedTemporaryFile(mode="b+w", delete=False, prefix="plng-", suffix=".bin") as local_file:
            try:
                local_file.write(remote_file.read())
            finally:
                local_file.close()
            return local_file.name, params["filename"]


def pl_get_doc_item(opener: urllib.request.OpenerDirector, doc_id: str) -> dict:
    """
    Loads the document item data (tags, correspondent, ...).

    :param opener: open director with credentials
    :param doc_id: document id.
    :return: document item
    """
    return pl_get(opener, "documents/", "".join([str(doc_id), "/"]))


def pl_get_doc_meta(opener: urllib.request.OpenerDirector, doc_id: str) -> dict:
    """
    Loads the document item data (tags, correspondent, ...).

    :param opener: open director with credentials
    :param doc_id: document id.
    :return: document item
    """
    return pl_get(opener, "documents/", "".join([str(doc_id), "/metadata/"]))


def pl_get_doc_items(opener: urllib.request.OpenerDirector, page: int, page_size: int = 20) -> (bool, list):
    """
    Loads a list of document items.

    :param opener: open director with credentials
    :param page: page to load (started by 1)
    :param page_size: page size
    :return: (bool,list) = More results; Result list of the requested page
    """
    page_result = pl_get(opener, "documents/", f"?page={page}&page_size={page_size}")

    if page_result["count"] > 0:
        more = page_result["next"] is not None
        result = page_result["results"]
        return more, result
    return False, []


def pl_get(opener: urllib.request.OpenerDirector, api: str, params: str):
    """
    Generic method to load a response from a GET method.

    :param opener: open director with credentials
    :param api: API name like 'tags/', 'document-types/'
    :param params: request parameters like '?page_size=1000'
    :return: The response
    """
    url = ''.join([pl_top_level_url, "api/", api, params])
    with contextlib.closing(opener.open(url)) as result:
        return json.load(result)


def get_result(opener: urllib.request.OpenerDirector, api: str, params: str):
    """
    Generic method to load a response from a GET method.

    :param opener: open director with credentials
    :param api: API name like 'tags/', 'document-types/'
    :param params: request parameters like '?page_size=1000'
    :return: The response
    """
    return pl_get(opener, api, params)["results"]


def dump_result(opener: urllib.request.OpenerDirector, api: str, params: str):
    """
    Dumps the id and name attributes of a response JSON array of objects.

    :param opener: open director with credentials
    :param api: API name like 'tags/', 'document-types/'
    :param params: request parameters like '?page_size=1000'
    """
    try:
        data = get_result(opener, api, params)
        for d in data:
            print(f"{d['id']} := {d['name']}")
    except IOError as e:
        print(e)


def dump_correspondents(opener: urllib.request.OpenerDirector, params: str):
    """
    Dumps correspondents from paperless-ng.

    :param opener: open director with credentials
    :param params: request parameters like '?page_size=1000'
    """
    dump_result(opener, "correspondents/", params)


def dump_tags(opener: urllib.request.OpenerDirector, params: str):
    """
    Dumps tags from paperless-ng.

    :param opener: open director with credentials
    :param params: request parameters like '?page_size=1000'
    """
    dump_result(opener, "tags/", params)


def dump_types(opener: urllib.request.OpenerDirector, params: str):
    """
    Dumps document types from paperless-ng.

    :param opener: open director with credentials
    :param params: request parameters like '?page_size=1000'
    """
    dump_result(opener, "document_types/", params)


def open_basic(tl_url: str, usn: str, pwd: str) -> urllib.request.OpenerDirector:
    """
    Basic Auth login handler.

    :param tl_url: top level domain for the endpoinds
    :param usn: username
    :param pwd: password
    :return: open director
    """
    basic_auth = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    basic_auth.add_password(None, tl_url, usn, pwd)

    auth_handler = urllib.request.HTTPBasicAuthHandler(basic_auth)
    opener = urllib.request.build_opener(auth_handler)
    urllib.request.install_opener(opener)

    return opener


# ########################
# docspell
##########################

class MultiPartForm:
    """
    Accumulate the data to be used when posting a form.

    A nice small class from https://pymotw.com/3/urllib.request/#uploading-files to avoid dependencies to other modules.
    """

    def __init__(self):
        self.form_fields = []
        self.files = []
        # Use a large random byte string to separate
        # parts of the MIME data.
        self.boundary = uuid.uuid4().hex.encode('utf-8')
        return

    def get_content_type(self):
        return 'multipart/form-data; boundary={}'.format(
            self.boundary.decode('utf-8'))

    def add_field(self, name, value):
        """Add a simple field to the form data."""
        self.form_fields.append((name, value))

    def add_file(self, fieldname, filename, fileHandle,
                 mimetype=None):
        """Add a file to be uploaded."""
        body = fileHandle.read()
        if mimetype is None:
            mimetype = (
                    mimetypes.guess_type(filename)[0] or
                    'application/octet-stream'
            )
        self.files.append((fieldname, filename, mimetype, body))
        return

    @staticmethod
    def _form_data(name):
        return ('Content-Disposition: form-data; '
                'name="{}"\r\n').format(name).encode('utf-8')

    @staticmethod
    def _attached_file(name, filename):
        return ('Content-Disposition: file; '
                'name="{}"; filename="{}"\r\n').format(
            name, filename).encode('utf-8')

    @staticmethod
    def _content_type(ct):
        return 'Content-Type: {}\r\n'.format(ct).encode('utf-8')

    def __bytes__(self):
        """Return a byte-string representing the form data,
        including attached files.
        """
        buffer = io.BytesIO()
        boundary = b'--' + self.boundary + b'\r\n'

        # Add the form fields
        pl
        for name, value in self.form_fields:
            buffer.write(boundary)
            buffer.write(self._form_data(name))
            buffer.write(b'\r\n')
            buffer.write(value.encode('utf-8'))
            buffer.write(b'\r\n')

        # Add the files to upload
        for f_name, filename, f_content_type, body in self.files:
            buffer.write(boundary)
            buffer.write(self._attached_file(f_name, filename))
            buffer.write(self._content_type(f_content_type))
            buffer.write(b'\r\n')
            buffer.write(body)
            buffer.write(b'\r\n')

        buffer.write(b'--' + self.boundary + b'--\r\n')
        return buffer.getvalue()


class DsHandler(urllib.request.BaseHandler):
    """
    DocSpell token auth handler.
    """

    token: str = None
    valid_until: int = 0
    realm: str = None
    url: str = None
    username: str = None
    password: str = None

    def http_request(self, req: urllib.request.Request):
        """
        Adds the `token` as "X-Docspell-Auth" header.

        :param req: the request to alter
        :return: the altered request
        """

        # Ignoring logins and session handling
        if req.selector.endswith("api/v1/open/auth/login"):
            return req
        if req.selector.endswith("api/v1/sec/auth/session"):
            return req

        # Check if we must refresh or login
        if self.need_login():
            self.login()
        else:
            if self.need_refresh():
                if not self.refresh():
                    self.login()

        # Now we can add the access token to the request
        req.add_header("X-Docspell-Auth", self.token)
        return req

    def add_password(self, realm, tl_url, usn, pwd):
        self.realm = realm
        self.url = tl_url
        self.username = usn
        self.password = pwd
        pass

    def set_token(self, t: str):
        self.token = t

    def set_valid_ms(self, valid_ms):
        self.valid_until = self.current_milli_time() + valid_ms

    def need_login(self):
        return (self.token is None) or ((self.current_milli_time() + 5 * 1000) > self.valid_until)

    def need_refresh(self):
        return (self.current_milli_time() + 30 * 1000) > self.valid_until

    def login(self) -> bool:
        token, valid_ms = ds_login_get_token(self.url, self.username, self.password)
        self.set_token(token)
        self.set_valid_ms(valid_ms)
        return token is not None

    def refresh(self) -> bool:
        token, valid_ms = ds_login_get_refresh(self.url, self.token)
        self.set_token(token)
        self.set_valid_ms(valid_ms)
        return token is not None

    @staticmethod
    def current_milli_time():
        return round(time.time() * 1000)


def ds_get(opener: urllib.request.OpenerDirector, api: str, params: str) -> json:
    """
    Generic GET/response method for DocSpell.

    :param opener: open handler with the access token
    :param api: API name, e.g "tag"
    :param params: extra request parameters
    :return: the response
    """
    url = ''.join([ds_top_level_url, "api/v1/sec/", api, params])
    with contextlib.closing(opener.open(url)) as result:
        return json.load(result)


def ds_get_result(opener: urllib.request.OpenerDirector, api: str, params: str = ""):
    """
    Generic result method for DocSpell.

    :param opener: open handler with the access token
    :param api: API name, e.g "tag"
    :param params: extra request parameters
    :return: the items of an responseresponse
    """
    return ds_get(opener, api, params)["items"]


def ds_dump_result(opener: urllib.request.OpenerDirector, api: str, params: str = ""):
    """
    Dumps a result (id and name) from a GET to DocSpell.

    :param opener: open handler with the access token
    :param api: API name, e.g "tag"
    :param params: extra request parameters
    """
    try:
        data = ds_get_result(opener, api, params)
        for d in data:
            print(f"{d['id']} := {d['name']}")
    except IOError as e:
        print(e)


def ds_dump_tags(opener: urllib.request.OpenerDirector):
    """
    Dumps all tags from DocSpell.

    :param opener: open handler with the access token
    """
    ds_dump_result(opener, "tag")


def ds_dump_equipment(opener: urllib.request.OpenerDirector):
    """
    Dumps all equipments from DocSpell.

    :param opener: open handler with the access token
    """
    ds_dump_result(opener, "equipment")


def ds_get_tags_with_category(opener: urllib.request.OpenerDirector, category: str) -> list:
    """
    Loads all tags with a specific category.

    :param opener: open handler with the access token
    :param category: the category to search for
    :return: list of tags
    """
    ds_types: list = []
    ds_tags = ds_get_result(opener, "tag")
    for tag in ds_tags:
        if tag["category"] == category:
            ds_types.append(tag.copy())
    return ds_types


def doc_type_exists(ds_doc_types: list, pl_doc_type: dict) -> bool:
    """
    Checks, if the paperless-ng doc type exists as tag in DocSpell.

    :param ds_doc_types: previously fetched tags from DocSpell
    :param pl_doc_type: previously fetched doc types from paperless-ng
    :return: True, if already exists
    """
    for dt in ds_doc_types:
        if dt["name"] == pl_doc_type["name"]:
            # Update the DS id
            pl_doc_type["ds-id"] = dt["id"]
            return True
    return False


def ds_create_tag(opener: urllib.request.OpenerDirector, name: str, category: str) -> bool:
    """
    Creates a tag in DocSpell.

    :param opener: open handler with the access token
    :param name: name of the tag
    :param category: category for the tag
    :return: True, if tag was created
    """
    payload = {"id": "ignored", "name": name, "category": category, "created": 0}
    return ds_post(opener, "tag", payload)


def ds_update_doc_types_as_tags(opener: urllib.request.OpenerDirector, pl_doc_types: list, category: str):
    """
    Creates tags in DocSpell from paperless-ng doc types.

    :param opener: open handler with the access token
    :param pl_doc_types: previously fetched doc types from paperless-ng
    :param category: the category to use for DocSpell tags (mimicking dock-types)
    """
    ds_doc_types = ds_get_tags_with_category(opener, category)
    for pl_doc_type in pl_doc_types:
        if not doc_type_exists(ds_doc_types, pl_doc_type):
            print(f"Need to create {pl_doc_type['name']}")
            if ds_create_tag(opener, pl_doc_type["name"], category):
                print("-> created.")
            else:
                print(f"-> not created, name '{pl_doc_type['name']}' "
                      f"exists but maybe with another category then '{category}'.")
        else:
            print(f"No create for {pl_doc_type['name']} the docspell id '{pl_doc_type['ds-id']}' exists.")


def ds_update_tags(opener: urllib.request.OpenerDirector, tags: list,
                   ignore_concerns: list, ignore_equipment: list, category: str):
    """
    Create tags in DocSpell from tags out of paperless-ng.

    :param opener: open handler with the access token
    :param tags: previously fetched tags from paperless-ng
    :param ignore_concerns: configured "persons of concern". The tags with these names will be ignored
    :param ignore_equipment: configured "equipments". The tags with these names will be ignored
    :param category: category for the new created tags
    :return:
    """
    ignore_names = []
    if ignore_concerns is not None:
        ignore_names.extend(set().union(*(d.keys() for d in ignore_concerns)))

    if ignore_equipment is not None:
        ignore_names.extend(set().union(*(d.keys() for d in ignore_equipment)))

    for tag in tags:
        if tag["name"] not in ignore_names:
            if ds_create_tag(opener, tag["name"], category):
                print(f"{tag['name']} created")
            else:
                print(f"{tag['name']} already exists")


def ds_create_person(opener: urllib.request.OpenerDirector, name: str, address: dict) -> bool:
    if not address:
        address = {"street": "", "zip": "", "city": "", "country": "DE"}

    payload = {
        "id": "ignore",
        "name": name,
        "organization": None,
        "address": address,
        "contacts": [],
        "notes": None,
        "use": "both",
        "created": 0
    }
    return ds_post(opener, "person", payload)


def ds_create_organization(opener: urllib.request.OpenerDirector, name: str, address: dict) -> bool:
    if not address:
        address = {"street": "", "zip": "", "city": "", "country": "DE"}

    payload = {
        "id": "ignore",
        "name": name,
        "address": address,
        "contacts": [],
        "notes": None,
        "use": "correspondent",
        "shortName": None,
        "created": 0
    }
    return ds_post(opener, "organization", payload)


def ds_update_concerns(opener: urllib.request.OpenerDirector, concerns: list, address: dict):
    """
    Creates persons from `concerns` configuration. Will be used later to link documents with similar labels to these
    persons.

    :param opener: open handler with the access token
    :param concerns: configured "persons of concern".
    :param address: default address configuration for all new created persons
    """
    for p in concerns:
        for k in p.keys():
            concern_name = p.get(k)
            if ds_create_person(opener, concern_name, address):
                print(f"person '{concern_name}' created.")
            else:
                print(f"person '{concern_name}' not created. Already exists.")


def ds_update_equipment(opener: urllib.request.OpenerDirector, equipment: list, equipment_def: dict):
    """
    Creates equipment from `equipment` configuration. Will be used later to link documents with similar labels to these
    equipments.

    :param opener: open handler with the access token
    :param equipment: configured "equipments".
    :param equipment_def: default data
    """

    use = str(deep_get(equipment_def, "use", "concerning"))
    note = deep_get(equipment_def, "note", None)
    for e in equipment:
        for k in e.keys():
            equipment_name = e.get(k)

            if ds_create_equipment(opener, equipment_name, use, note):
                print(f"equipment '{equipment_name}' created.")
            else:
                print(f"equipment '{equipment_name}' not created. Already exists.")


def ds_create_equipment(opener: urllib.request.OpenerDirector, name: str, use: str, note: str) -> bool:
    """
    Creates equipment in DocSpell.

    :param opener: open handler with the access token
    :param name: name of the equipment
    :param use: usage ("concerning" or "disabled")
    :param note: notes for the equipment
    :return: True, if equipment was created
    """
    payload = {"id": "ignored", "name": name, "use": use, "notes": note, "created": 0}
    return ds_post(opener, "equipment", payload)


def get_mapped_correspondent(correspondent, mapping) -> dict:
    for m in mapping:
        for k in m.keys():
            if correspondent["name"] == k:
                return m
    return {}


def ds_create_correspondent(opener: urllib.request.OpenerDirector, corres_type: str, name: str, address: dict) -> bool:
    if corres_type == "person":
        return ds_create_person(opener, name, address)
    else:
        return ds_create_organization(opener, name, address)


def ds_update_correspondents(opener: urllib.request.OpenerDirector,
                             correspondents, mapping, corr_def_type: str):
    for correspondent in correspondents:
        address = {}
        name = correspondent["name"]
        correspondent_type = corr_def_type
        mc = get_mapped_correspondent(correspondent, mapping)
        if mc:
            data = mc.get(name)
            name = deep_get(data, "name", name)
            correspondent_type = deep_get(data, "create-as", correspondent_type)
            address = deep_get(data, "address", {})
        if ds_create_correspondent(opener, correspondent_type, name, address):
            print(f"correspondent {correspondent_type} {name} created.")
        else:
            print(f"correspondent {correspondent_type} {name} not created. Already exists")


def ds_check_doc(opener: urllib.request.OpenerDirector, checksum: str) -> dict:
    """
    Checks if the document with the SHA-256 checksum was already uploaded.

    :param opener: open handler with the access token
    :param checksum: SHA-256 checksum encoded as hex-digest
    :return: the document ID or None (if not found)
    """
    items = ds_get_result(opener, "checkfile", "".join(["/", checksum]))
    if items:
        return items[0]


def ds_get_doc_item(opener: urllib.request.OpenerDirector, id: str) -> json:
    """
    Retrieves the document item meta data.

    :param opener: open handler with the access token
    :param id: document item ID
    :return: the item JSON structure
    """
    return ds_get(opener, "item", "".join(["/", id]))


def ds_upload_doc(opener: urllib.request.OpenerDirector, path: str, filename: str, content_type: str) -> bool:
    """
    Uploads a file to docspell. Please check before if the document already exists, because this method can create
    duplicates.

    :param opener: open handler with the access token
    :param path: path to the local file
    :param filename: name of the file
    :param content_type: content type of the file
    :return: True if upload was successful
    """
    url = ''.join([ds_top_level_url, 'api/v1/sec/', 'upload/item'])

    form = MultiPartForm()
    form.add_file("file", filename, fileHandle=open(path, "r+b"), mimetype=content_type)
    # form.add_field("type", content_type)

    data = bytes(form)

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", form.get_content_type())
    req.add_header("Content-Length", str(len(data)))

    with contextlib.closing(opener.open(req, data)) as response:
        result = json.load(response)
        return result["success"]


def ds_upload_doc_unique(opener: urllib.request.OpenerDirector,
                         path: str, filename: str, content_type: str) -> (str, bool):
    """
    Checks, if the document exists. If not, uploads the document and wait for the processing.
    Maybe blocks for a while.

    :param opener: open handler with the access token
    :param path: path to the local file
    :param filename: name of the file
    :param content_type: content type of the file
    :return: str,bool = id of the uploaded / processed document; already-exists
    """
    original_hash = sha256(path)

    item_data = ds_check_doc(opener, original_hash)

    doc_exists = False
    count = 0
    count_max = 25
    if not item_data:
        print(f"Upload {filename} ", end="")
        ds_upload_doc(opener, path, filename, content_type)
        while count <= count_max:
            item_data = ds_check_doc(opener, original_hash)
            if not item_data:
                count = count + 1
                print(".", end="")
                time.sleep(count * count)
            else:
                print(f" done, id = {item_data['id']}")
                break
    else:
        print(f"Already existing {filename}, id = {item_data['id']}")
        doc_exists = True

    if item_data:
        return item_data["id"], doc_exists
    else:
        if count >= count_max:
            print(" processing not finished. Not waiting anymore.")


def sha256(filename: str) -> str:
    """
    Calculates the SHA-256 checksum of a file.

    :param filename: filename
    :return: hex digest as str
    """
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def ds_document_update_correspondent_org (opener: urllib.request.OpenerDirector, doc_id: str, corr_id: str) -> bool:
    """
    Updates the correspondent as organization in a document.

    :param opener: open handler with the access token
    :param doc_id: docspell document id
    :param corr_id: docspell organization id
    :return: True if successful
    """
    return ds_put(opener, "".join(["item/", doc_id, "/corrOrg"]), {"id": corr_id})


def ds_document_update_correspondent_person (opener: urllib.request.OpenerDirector, doc_id: str, pers_id: str) -> bool:
    """
    Updates the correspondent as organization in a document.

    :param opener: open handler with the access token
    :param doc_id: docspell document id
    :param pers_id: docspell person id
    :return: True if successful
    """
    return ds_put(opener, "".join(["item/", doc_id, "/corrPerson"]), {"id": pers_id})


def ds_document_update_concerning_person (opener: urllib.request.OpenerDirector, doc_id: str, pers_id: str) -> bool:
    """
    Updates the concerning person in a document.

    :param opener: open handler with the access token
    :param doc_id: docspell document id
    :param pers_id: docspell person id
    :return: True if successful
    """
    return ds_put(opener, "".join(["item/", doc_id, "/concPerson"]), {"id": pers_id})


def ds_document_update_equipment (opener: urllib.request.OpenerDirector, doc_id: str, eqpm_id: str) -> bool:
    """
    Updates the concerning person in a document.

    :param opener: open handler with the access token
    :param doc_id: docspell document id
    :param eqpm_id: docspell equipment id
    :return: True if successful
    """
    return ds_put(opener, "".join(["item/", doc_id, "/concEquipment"]), {"id": eqpm_id})


def ds_document_update_name (opener: urllib.request.OpenerDirector, doc_id: str, title: str) -> bool:
    """
    Updates the document name of a document.

    :param opener: open handler with the access token
    :param doc_id: docspell document id
    :param title: title of the document
    :return: True if successful
    """
    return ds_put(opener, "".join(["item/", doc_id, "/name"]), {"text": title})


def ds_document_update_date (opener: urllib.request.OpenerDirector, doc_id: str, date: datetime) -> bool:
    """
    Updates the document date of a document.

    :param opener: open handler with the access token
    :param doc_id: docspell document id
    :param date: date of the document
    :return: True if successful
    """
    corrected = date.replace(hour=12, minute=0, second=0, microsecond=0)
    epoc_ms = round(corrected.timestamp()*1000)
    return ds_put(opener, "".join(["item/", doc_id, "/date"]), {"date": epoc_ms})


def ds_document_update_tags (opener: urllib.request.OpenerDirector, doc_id: str, tags: list) -> bool:
    """
    Updates the document date of a document.

    :param opener: open handler with the access token
    :param doc_id: docspell document id
    :param tags: a list of tags
    :return: True if successful
    """
    return ds_put(opener, "".join(["item/", doc_id, "/taglink"]), {"items": tags})


def check_match (records: list, matched: dict, ignore: set = None) -> dict:
    """
    Validates if everything was matched.

    :param records: records to check
    :param matched: matched records
    :param ignore: ignore this id's in set
    :return: unmatched records
    """
    if ignore is None:
        ignore = {}
    unmatched: dict = {}
    for r in records:
        if r["id"] in ignore:
            continue
        if not r["id"] in matched:
            unmatched[r["id"]] = {"name": r["name"]}
    return unmatched


def ds_match_doctypes(config: json, paperless: urllib.request.OpenerDirector,
                       docspell: urllib.request.OpenerDirector) -> (dict, dict):
    """
    Creates a mapping between paperless-ng doc-types and DocSpell tags.

    :param config: configuration
    :param paperless: access handler for paperless-ng
    :param docspell: docspell open handler with the access token
    :return: (dict, dict) = mapped DocSpell tags; unmapped doc-types from paperless-ng
    """
    matched: dict = {}
    imp_doctype = deep_get(config, "docspell.doc-type.import", "tag")
    imp_doctype_name = deep_get(config, "docspell.doc-type.name", "Document type")
    pl_limit = deep_get(config, "paperless-ng.classification-limit", 9999)

    if imp_doctype == "tag":
        # Import of doc types as tags
        pl_doc_types = get_result(paperless, "document_types/", f"?page_size={pl_limit}")
        ds_doc_types = ds_get_tags_with_category(docspell, str(imp_doctype_name))
        for pl_doc_type in pl_doc_types:
            for ds_doc_type in ds_doc_types:
                if ds_doc_type["name"] != pl_doc_type["name"]:
                    continue
                matched[pl_doc_type["id"]]={"ds-id": ds_doc_type["id"], "name": pl_doc_type["name"]}
                break

        return matched, check_match(pl_doc_types, matched)

    return {},{}



def ds_match_tags(opener: urllib.request.OpenerDirector, pl_tags, concerns, equipment) -> (dict, dict):
    """
    Creates a mapping between paperless-ng tags and DocSpell tags.

    :param opener: open handler with the access token
    :param pl_tags: paperless-ng tags
    :param concerns: person of concern mapping
    :param equipment: equipment mapping
    :return: (dict, dict) = mapped DocSpell tags; unmapped tags from paperless-ng
    """
    matched: dict = {}
    ignore_id = set()
    ignore_name = set()

    for c in concerns:
        ignore_name.update(c.keys())
    for e in equipment:
        ignore_name.update(e.keys())

    ds_tags = ds_get_result(opener, "tag")

    for ds_tag in ds_tags:
        for pl_tag in pl_tags:
            if pl_tag["name"] in ignore_name:
                ignore_id.add(pl_tag["id"])
                continue
            if pl_tag["id"] in matched:
                continue
            if ds_tag["name"] != pl_tag["name"]:
                continue

            matched[pl_tag["id"]] = {"ds-id": ds_tag["id"], "name": pl_tag["name"]}
            break

    return matched, check_match(pl_tags, matched, ignore_id)


def ds_match_equipment(opener: urllib.request.OpenerDirector, pl_tags, equipment) -> (dict, dict):
    """
    Creates a mapping between paperless-ng tags and DocSpell equipment.

    :param opener: open handler with the access token
    :param pl_tags: paperless-ng tags
    :param equipment: equipment mapping
    :return: (dict, dict) = mapped DocSpell equipment; unmapped tags from paperless-ng
    """

    if not equipment:
        return {},{}

    matched: dict = {}
    ignore_id = set()
    all_equipments: dict = {}

    # Flatten the List of records to a dict:
    for e in equipment:
        for k in e.keys():
            all_equipments[k] = e[k]

    ds_equipments = ds_get_result(opener, "equipment")
    for pl_tag in pl_tags:
        if pl_tag["name"] in all_equipments:
            for ds_equipment in ds_equipments:
                if ds_equipment["name"] != all_equipments[pl_tag["name"]]:
                    continue

                matched[pl_tag["id"]] = {"ds-id": ds_equipment["id"], "name": pl_tag["name"]}
                break
        else:
            ignore_id.add(pl_tag["id"])

    return matched, check_match(pl_tags, matched, ignore_id)


def ds_match_concerns(opener: urllib.request.OpenerDirector, pl_tags, concerns) -> (dict, dict):
    """
    Creates a mapping between paperless-ng tags and DocSpell "person of concerns".

    :param opener: open handler with the access token
    :param pl_tags: paperless-ng tags
    :param concerns: person of concern mapping
    :return: (dict, dict) = mapped DocSpell persons; unmatched records
    """
    if not concerns:
        return {},{}

    matched: dict = {}
    ignore_id = set()
    all_concerns: dict = {}

    # Flatten the List of records to a dict:
    for e in concerns:
        for k in e.keys():
            all_concerns[k] = e[k]

    ds_persons = ds_get_result(opener, "person")
    for pl_tag in pl_tags:
        if pl_tag["name"] in all_concerns:
            for ds_person in ds_persons:
                if ds_person["name"] != all_concerns[pl_tag["name"]]:
                    continue

                matched[pl_tag["id"]] = {"ds-id": ds_person["id"], "name": pl_tag["name"]}
                break
        else:
            ignore_id.add(pl_tag["id"])

    return matched, check_match(pl_tags, matched, ignore_id)


def create_correspondent_dict(correspondents, correspondents_mapping, corr_default_type):
    """
    Merges the correspondent records together with the configured correspondents_mapping for later matching.

    :param correspondents: the correspondent records from paperless-ng
    :param correspondents_mapping: the mapped values from the config file
    :param corr_default_type: the default type (organization or person)
    :return: a dictionary of correspondents with id, name and type
    """
    all_corrs: dict = {}
    # Flatten dict with mapping and default type (organization or person) if not defined
    for c in correspondents_mapping:
        for k in c.keys():
            all_corrs[k] = c[k]
            if "create-as" not in all_corrs[k]:
                all_corrs[k]["create-as"] = corr_default_type
    # Enhance the dict with the un-mapped correspondents from paperless-ng
    for c in correspondents:
        if c["name"] in all_corrs:
            all_corrs[c["name"]]["id"] = c["id"]
        else:
            all_corrs[c["name"]] = {"name": c["name"], "id": c["id"], "create-as": corr_default_type}
    return all_corrs


def ds_match_organizations(opener: urllib.request.OpenerDirector,
                           pl_correspondents, pl_corr_mapping, pl_corr_def_type) -> (dict, dict):
    """
    Creates a mapping between paperless-ng correspondents and DocSpell organizations.

    :param opener: open handler with the access token
    :param pl_correspondents: paperless-ng correspondents
    :param pl_corr_mapping: paperless-ng correspondents mapping to distinguish between persons and organizations
    :param pl_corr_def_type: default correspond type
    :return: (dict, dict) = mapped DocSpell organizations; unmatched records
    """
    if not pl_correspondents:
        return {},{}

    matched: dict = {}
    ignore_id = set()

    all_corrs = create_correspondent_dict(pl_correspondents, pl_corr_mapping, pl_corr_def_type)
    ds_organizations = ds_get_result(opener, "organization")
    for k in all_corrs.keys():
        corr = all_corrs[k]
        if corr["create-as"] == "person":
            ignore_id.add (corr["id"])
            continue
        for ds_organization in ds_organizations:
            if corr["name"] != ds_organization["name"]:
                continue
            matched[corr["id"]]= {"ds-id": ds_organization["id"], "name": corr["name"]}
            break

    return matched, check_match(pl_tags, matched, ignore_id)



def ds_match_persons(opener: urllib.request.OpenerDirector,
                     pl_correspondents, pl_corr_mapping, pl_corr_def_type) -> (dict, dict):
    """
    Creates a mapping between paperless-ng correspondents and DocSpell persons.

    :param opener: open handler with the access token
    :param pl_correspondents: paperless-ng correspondents
    :param pl_corr_mapping: paperless-ng correspondents mapping to distinguish between persons and organizations
    :param pl_corr_def_type: default correspond type
    :return: (dict, dict) = mapped DocSpell organizations; unmatched records
    """
    if not pl_correspondents:
        return {},{}
    matched: dict = {}
    ignore_id = set()

    all_corrs = create_correspondent_dict(pl_correspondents, pl_corr_mapping, pl_corr_def_type)
    ds_persons = ds_get_result(opener, "person")
    for k in all_corrs.keys():
        corr = all_corrs[k]
        if corr["create-as"] == "organization":
            ignore_id.add (corr["id"])
            continue
        for ds_person in ds_persons:
            if corr["name"] != ds_person["name"]:
                continue
            matched[corr["id"]]= {"ds-id": ds_person["id"], "name": corr["name"]}
            break

    return matched, check_match(pl_tags, matched, ignore_id)



def ds_write(opener: urllib.request.OpenerDirector, api: str, payload: json, method: str = "POST") -> bool:
    """
    Generic write method to store a JSON payload to DocSpell.

    :param opener: open handler with the access token
    :param api: API name, e.g. "tag", "person" ...
    :param payload: JSON payload to POST
    :param method: method to use on request (POST, PUT)
    :return: True, if successful
    """
    url = ''.join([ds_top_level_url, 'api/v1/sec/', api])
    json_data = json.dumps(payload)
    json_data_as_bytes = json_data.encode('utf-8')
    req = urllib.request.Request(url, data=json_data_as_bytes, method=method)
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('Content-Length', str(len(json_data_as_bytes)))

    with contextlib.closing(opener.open(req, json_data_as_bytes)) as response:
        result = json.load(response)
        return result["success"]


def ds_post(opener: urllib.request.OpenerDirector, api: str, payload: json) -> bool:
    """
    Generic POST method to store a JSON payload to DocSpell.

    :param opener: open handler with the access token
    :param api: API name, e.g. "tag", "person" ...
    :param payload: JSON payload to POST
    :return: True, if successful
    """
    return ds_write(opener, api, payload, "POST")


def ds_put(opener: urllib.request.OpenerDirector, api: str, payload: json) -> bool:
    """
    Generic POST method to store a JSON payload to DocSpell.

    :param opener: open handler with the access token
    :param api: API name, e.g. "tag", "person" ...
    :param payload: JSON payload to POST
    :return: True, if successful
    """
    return ds_write(opener, api, payload, "PUT")


def ds_login_get_token(tl_url: str, usn: str, pwd: str) -> (str, int):
    """
    Login to DocSpell and load a token.

    :param tl_url: top level domain for DocSpell.
    :param usn: username
    :param pwd: password
    :return: access token
    """
    url = ''.join([tl_url, 'api/v1/open/auth/login'])
    payload = {'account': usn, 'password': pwd}

    json_data = json.dumps(payload)
    json_data_as_bytes = json_data.encode('utf-8')

    req = urllib.request.Request(url, data=json_data_as_bytes)
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('Content-Length', str(len(json_data_as_bytes)))

    with contextlib.closing(urllib.request.urlopen(req, json_data_as_bytes)) as response:
        data = json.load(response)
        if data["success"]:
            return data["token"], data["validMs"]


def ds_login_get_refresh(tl_url: str, token: str) -> (str, int):
    """
    Creates a new token by refreshing the session.

    :param tl_url: top level domain for DocSpell.
    :param token: previous valid access token
    :return: the new token and valid milliseconds
    """
    url = ''.join([tl_url, 'api/v1/sec/auth/session'])
    json_data = json.dumps({})
    json_data_as_bytes = json_data.encode('utf-8')
    req = urllib.request.Request(url, data=json_data_as_bytes)
    req.add_header('X-Docspell-Auth', token)
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('Content-Length', str(len(json_data_as_bytes)))

    with contextlib.closing(urllib.request.urlopen(req, json_data_as_bytes)) as response:
        data = json.load(response)
        if data["success"]:
            return data["token"], data["validMs"]


def open_token(tl_url: str, usn: str, pwd: str) -> urllib.request.OpenerDirector:
    """
    Login to DocSpell and create an open director with an access token handler.
    :param tl_url: top level domain for DocSpell.
    :param usn: username
    :param pwd: password
    :return: open director with access token handler
    """
    ds_auth = DsHandler()
    ds_auth.add_password(None, tl_url, usn, pwd)

    opener = urllib.request.build_opener(ds_auth)
    urllib.request.install_opener(opener)

    return opener


def parse_datetime(s:str) -> datetime:
    """
    Parses JSON date/time with optional nanoseconds.
    :param s: string to parse
    :return: datetime
    """
    if not s:
        return None
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")
    except:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")


def title(t:str):
    print("\n" + t)
    print("=" * len(t))


# ########################
# Import methods
##########################


def import_document_types(config: json,
                          paperless: urllib.request.OpenerDirector, docspell: urllib.request.OpenerDirector):
    """
    Imports the document types.

    :param config: configuration
    :param paperless: open handler to manage the authentication to paperless-ng
    :param docspell:  open handler to manage the authentication to docspell
    """
    imp_doctype = deep_get(config, "docspell.doc-type.import", "tag")
    imp_doctype_name = deep_get(config, "docspell.doc-type.name", "Document type")

    if imp_doctype == "tag":
        # Import of doc types as tags
        doc_types = get_result(paperless, "document_types/", "?page_size=1000")
        ds_update_doc_types_as_tags(docspell, doc_types, str(imp_doctype_name))
        pass
    elif imp_doctype == "none":
        print("Ignoring document-types on import")
        pass
    elif imp_doctype == "custom":
        # Import of doc types as custom field
        raise ValueError("custom field import for document-types are not supported yet")
    elif imp_doctype == "folder":
        # Import of doc types as folder
        raise ValueError("folder import for document-types are not supported yet")


# #### Load configuration and prepare connections
configuration = load_config()

pl_top_level_url = configuration['paperless-ng']['url']
ds_top_level_url = configuration['docspell']['url']

paperless_handler = open_basic(pl_top_level_url,
                               configuration['paperless-ng']['username'],
                               configuration['paperless-ng']['password'])
docspell_handler = open_token(ds_top_level_url,
                              configuration['docspell']['username'],
                              configuration['docspell']['password'])

pl_limit = deep_get(configuration, "paperless-ng.classification-limit", 9999)

# #### Importing document types
title("Import document types")
import_document_types(configuration, paperless_handler, docspell_handler)

# #### Importing tags
title("Import document tags")
# some tags in paperless are persons of concern. This is the mapping:
concerns = deep_get(configuration, "docspell.tags.concerns.mapping", None)
# some other tags maybe equipment
equipment = deep_get(configuration, "docspell.tags.equipment.mapping", None)
tag_category = deep_get(configuration, "docspell.tags.category", None)

# Load tags from paperless-ng
pl_tags = get_result(paperless_handler, "tags/", f"?page_size={pl_limit}")

# Update tags, excluding concerns
ds_update_tags(docspell_handler, pl_tags, concerns, equipment, str(tag_category))

# #### Importing concerns
title("Import persons of concern")
address_default = deep_get(configuration, "docspell.tags.concerns.default", None)
if concerns is not None:
    ds_update_concerns(docspell_handler, concerns, address_default)

# #### Importing equipment
title("Import equipment")
equipment_default = deep_get(configuration, "docspell.tags.equipment.default", None)
if equipment is not None:
    ds_update_equipment(docspell_handler, equipment, equipment_default)

# #### Importing correspondents
title("Import correspondents")
pl_correspondents = get_result(paperless_handler, "correspondents/", f"?page_size={pl_limit}")
pl_corr_mapping = deep_get(configuration, "docspell.correspondents.mapping")
pl_corr_def_type = deep_get(configuration, "docspell.correspondents.default.create-as", "organization")

if pl_corr_def_type not in ["person", "organization"]:
    raise ValueError(f"Configuration 'docspell.correspondents.default.create-as' wrong. "
                     f"{pl_corr_def_type} not allowed.")

if pl_correspondents:
    ds_update_correspondents(docspell_handler, pl_correspondents, pl_corr_mapping, pl_corr_def_type)

# #### match paperless classifications with docspell; check if everything is fine to link it to the documents
title("Check imported classification data")
type_dict, type_unmatched = ds_match_doctypes(configuration, paperless_handler, docspell_handler)
if type_unmatched:
    raise ValueError (f"Unexpected issue with unmatched document types: {type_unmatched}")

tags_dict, tags_unmatched = ds_match_tags(docspell_handler, pl_tags, concerns, equipment)
if tags_unmatched:
    raise ValueError (f"Unexpected issue with unmatched tags: {tags_unmatched}")

eqpm_dict, eqpm_unmatched = ds_match_equipment(docspell_handler, pl_tags, equipment)
if eqpm_unmatched:
    raise ValueError (f"Unexpected issue with unmatched equipment: {eqpm_unmatched}")

conc_dict, conc_unmatched = ds_match_concerns(docspell_handler, pl_tags, concerns)
if conc_unmatched:
    raise ValueError (f"Unexpected issue with unmatched concerning persons: {conc_unmatched}")

orga_dict, orga_unmatched = ds_match_organizations(docspell_handler,
                                                   pl_correspondents, pl_corr_mapping, pl_corr_def_type)
if orga_unmatched:
    raise ValueError (f"Unexpected issue with unmatched correspondent organizations: {orga_unmatched}")

pers_dict, pers_unmatched = ds_match_persons(docspell_handler,
                                             pl_correspondents, pl_corr_mapping, pl_corr_def_type)
if pers_unmatched:
    raise ValueError (f"Unexpected issue with unmatched correspondent persons: {pers_unmatched}")

# #### Importing documents
title("Import documents")
page_size = int(str(deep_get(configuration, "page-size", 20)))
limit_items = int(str(deep_get(configuration, "limit", 0)))
update_existing = deep_get(configuration, "update-existing", False)
imp_doctype = deep_get(configuration, "docspell.doc-type.import", "tag")

page_no: int = 1
more: bool = True
item_count: int = 0
item_updated_count: int = 0

while more:
    more, pl_items = pl_get_doc_items(paperless_handler, page_no, page_size)
    if pl_items:
        for pl_item in pl_items:
            pl_doc_id = pl_item['id']
            # Download the document from paperless-ng
            pl_doc_path, pl_doc_name = pl_download_document(paperless_handler, pl_doc_id)

            pl_doc_meta = pl_get_doc_meta(paperless_handler, pl_doc_id)

            # Upload the document to DocSpell and wait for processing
            ds_doc_id, ds_doc_exists = \
                ds_upload_doc_unique(docspell_handler,
                                     pl_doc_path, pl_doc_name, pl_doc_meta["original_mime_type"])

            print(f"{pl_doc_id}:={pl_item['title']}, "
                  f"correspondent={pl_item['correspondent']}, tags={pl_item['tags']}, downloaded={pl_doc_path}, "
                  f"id={ds_doc_id}")

            # Delete the local temporary file
            os.remove(pl_doc_path)

            if update_existing or not ds_doc_exists:
                # continue with updating the documents with item data (tags, correspondent, concerns, equipment)

                # correspondent organization or person:
                if pl_item["correspondent"]:
                    if pl_item["correspondent"] in orga_dict:
                        ds_document_update_correspondent_org(docspell_handler,
                                                             ds_doc_id, orga_dict[pl_item["correspondent"]]["ds-id"])
                    elif pl_item["correspondent"] in pers_dict:
                        ds_document_update_correspondent_person(docspell_handler,
                                                             ds_doc_id, pers_dict[pl_item["correspondent"]]["ds-id"])
                else:
                    if not ds_doc_exists:
                        # If it's a new document, we remove the "guessed" correspondent
                        ds_document_update_correspondent_org(docspell_handler, ds_doc_id, None)
                        ds_document_update_correspondent_person(docspell_handler, ds_doc_id, None)

                # Name
                ds_document_update_name(docspell_handler, ds_doc_id, pl_item["title"])

                # Date
                pl_created: datetime = parse_datetime(pl_item["created"])
                ds_document_update_date(docspell_handler, ds_doc_id, pl_created)

                # Simple tags, tags as persons and tags as equipment
                if pl_item["tags"]:
                    ds_tags: list = []
                    ds_concerning = None
                    ds_equipment = None

                    # Document types
                    if pl_item["document_type"]:
                        if imp_doctype == "tag":
                            if pl_item["document_type"] in type_dict:
                                ds_tags.append(type_dict[pl_item["document_type"]]["ds-id"])

                    for pl_tag in pl_item["tags"]:
                        if pl_tag in tags_dict:
                            ds_tags.append(tags_dict[pl_tag]["ds-id"])
                        elif pl_tag in conc_dict:
                            if not ds_concerning:
                                ds_concerning=conc_dict[pl_tag]["ds-id"]
                        elif pl_tag in eqpm_dict:
                            if not ds_equipment:
                                ds_equipment=eqpm_dict[pl_tag]["ds-id"]

                    if ds_tags:
                        ds_document_update_tags(docspell_handler, ds_doc_id, ds_tags)

                    if ds_concerning or not ds_doc_exists:
                        ds_document_update_concerning_person(docspell_handler, ds_doc_id, ds_concerning)

                    if ds_equipment or not ds_doc_exists:
                        ds_document_update_equipment(docspell_handler, ds_doc_id, ds_equipment)

                item_updated_count += 1

            item_count += 1

            # We stop earlier if we have a limit:
            if limit_items and (item_count >= limit_items):
                more = False
                break
        page_no = page_no + 1
print("")
print(f"Documents processed: {item_count}; "
      f"updated: {item_updated_count}; "
      f"limit: {limit_items if limit_items>0 else 'unlimited'}")
