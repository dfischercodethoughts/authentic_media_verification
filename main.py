import random

from PIL import Image
import sys
from Crypto.PublicKey import RSA
from hashlib import sha512
import json
import numpy as np


class Assertion:
    def __init__(self, name:str, params=None, asset_hash = None,additional_info = None):
        self.name = name
        if params:
            self.params = params
        else:
            self.params=[]
        if additional_info:
            self.other_data = additional_info # json
        else:
            self.other_data = "none"
        self.asset_hash = asset_hash

    def __hash__(self):
        if self.params:
            return hash(self.name + str([param for param in self.params]) + str(self.asset_hash))
        else:
            return hash(self.name + str(self.asset_hash))

    def __str__(self):
        return "name: {} \n asset hash: {} \n params:{}".format(self.name,str(self.asset_hash),",".join([str(p) for p in self.params]))


class Claim:
    def __init__(self):
        self.asset_hash = None
        self.parent = None
        self.assertions = [] #list of assertion ids
        self.signature = None

    def create_from_im_metadata(self,im_metadata,assertions,im, keypair):
        self.asset_hash = int.from_bytes(sha512(str(np.array(im)).encode('utf-8')).digest(), byteorder="big")
        self.signature = pow(self.asset_hash,keypair.d,keypair.n)
        self.parent = im_metadata.claims["head"]["asset_hash"]
        self.assertions = assertions

    def create_from_json(self,in_json):
        print("\ncreating from the following json:")
        print(in_json)
        self.asset_hash = in_json["asset_hash"]
        self.parent = in_json["parent"]
        self.assertions = [assertion_id for assertion_id in in_json["assertions"]]
        self.signature = in_json["signature"]
        print("final result: " + str(self))

    def write_to_json(self):
        out_str = "{\n\t"
        out_str += "\"asset_hash\":{},\n\t".format(self.asset_hash)
        out_str += "\"parent\":\"{}\",\n\t".format(self.parent)
        out_str += "\"assertions\": [" + ",".join(['"' + str(assertion) + '"' for assertion in self.assertions]) + "],\n\t"
        out_str += "\"signature\":{}\n".format(self.signature)
        out_str += "}"
        return out_str

    def __str__(self):
        return str(self.asset_hash)

    def __hash__(self):
        return int.from_bytes(sha512(str(self.asset_hash).encode('utf-8') + str(self.parent).encode('utf-8') + "".join([str(asser) for asser in self.assertions]).encode('utf-8') + str(self.signature).encode('utf-8')).digest(),byteorder="big")


class ImageMetaData:
    def __init__(self):
        self.claims = None #json
        self.assertions = {} # map from assertion id to image hash

    def __str__(self):
        return "claims: {}\nassertions: {}".format(self.claims,[ str(val) for val in self.assertions.values()])
#
# class ImageWithMetaData:
#     def __init__(self,filename = None):
#         self.claims = None
#         self.assertions = []
#         self.filename = filename
#         if filename:
#             self.folder = filename[0:filename.find(".")]
#             self.image = Image.open(self.folder + "\\" + filename)
#             # assertion_file = open(self.folder + "\\assertions.txt")
#             # claim_file = open(self.folder + "\\claims.txt")
#             self.claims = json.load(self.folder + "\\claims.json")
#         else:
#             self.folder = None
#             self.image = None
#
#     def perform_modification(self,modification_name,args):
#         if modification_name == "crop":
#             result = self.image.resize((int(args[0]),int(args[1])))
#             assertion = Assertion(modification_name,args,int.from_bytes(sha512(str(result)).digest(),byteorder="big"))
#             self.assertions.append(assertion)


class Client:
    """Clients can take an image and claim and ask if the claim matches what the server knows"""
    def __init__(self):
        self.filename = ""
        self.image = ""
        self.claim = None


class Server:
    """Servers accept request from client in the form of [perform modifications (start_image, end_image, assertions)] or
        [verify authenticity (image, claim)]"""
    def __init__(self):
        self.keypair = RSA.generate(bits=1024)
        self.db = {} # this should be implemented using a decentralized ethereum database

    def create_new_image(self,im:Image,additional_info=None):
        if self.db.get(str(np.array(im))):
            return -1
        else:
            newmetadata = ImageMetaData()
            init_assert = Assertion("init",asset_hash=int.from_bytes(sha512(str(np.array(im)).encode('utf-8')).digest(),byteorder="big"),additional_info= additional_info)
            first_claim = Claim()
            first_claim.assertions.append(hash(init_assert))
            first_claim.asset_hash = int.from_bytes(sha512(str(np.array(im)).encode('utf-8')).digest(),byteorder="big")
            first_claim.parent = "header " + str(random.random())
            first_claim.signature = pow(int.from_bytes(sha512(str(np.array(im)).encode('utf-8')).digest(),byteorder = "big"),self.keypair.d,self.keypair.n)
            newmetadata.assertions[hash(init_assert)] = init_assert
            # print(first_claim.write_to_json())
            json_str_first_claim = "{\"head\":" + first_claim.write_to_json() + ",\n \"body\":[]}"
            # print(json_str_first_claim)
            # print(json_str_first_claim)
            newmetadata.claims = json.loads(json_str_first_claim)
            self.db[str(np.array(im))] = newmetadata
            return 1

    def perform_modifications(self,in_im:Image,out_im: Image,mods:json,other_info = None):
        #mods is a json list of json dictionaries
        im_meta_data = self.db.get(str(np.array(im)))
        tmp_assertions = []
        result = in_im
        for mod in mods:
            # print(mod)
            name = mod["name"]
            args = mod["args"]
            if name == "crop" or name == "resize":
                result = result.resize((int(args[0]),int(args[1])))
                new_assert = Assertion(name,args,int.from_bytes(sha512(str(np.array(result)).encode('utf-8')).digest(),byteorder="big"),other_info)
                assert_id = hash(new_assert)
                im_meta_data.assertions[assert_id] = new_assert
                tmp_assertions.append(assert_id)
            if not result:
                return-1
        newclaim = Claim()
        newclaim.create_from_im_metadata(im_metadata=im_meta_data,assertions=tmp_assertions,im = result,keypair=self.keypair)
        if out_im != result:
            print("ERROR: applying alterations to input image does not result in output image")
        old_head = im_meta_data.claims["head"]
        im_meta_data.claims["head"] = newclaim.write_to_json()
        im_meta_data.claims["body"].append(old_head)
        self.db[str(np.array(result))] = im_meta_data

    def verify_metadata(self,im: Image, claim : Claim):
        if self.db.get(str(np.array(im))):
            known_metadata = self.db[str(np.array(im))]
            # most_recent_claim = known_metadata.claims["head"]
            most_recent_claim = Claim()
            most_recent_claim.create_from_json(json.loads(known_metadata.claims["head"]))
            print("most recent: {}".format(most_recent_claim))
            print("presented: {}".format(claim))

            if hash(most_recent_claim) == hash(claim):
                return "Claim presented is most recent claim"
            else:
                return "Claim presented is outdated or invalid"
        else:
            return "Image not found"

    def get_all_claims(self,im:Image):
        if self.db.get(str(np.array(im))):
            metadat = self.db.get(str(np.array(im)))
            claims_to_ret = []
            tmp = Claim()
            tmp.create_from_json(metadat["head"])
            claims_to_ret.append(tmp)
            for claim_dat in metadat["body"]:
                tmp = Claim()
                tmp.create_from_json(claim_dat)
                claims_to_ret.append(tmp)
            return claims_to_ret
        else:
            return []

    def get_metadata(self,im:Image):
        return self.db.get(str(np.array(im)))


if __name__ == "__main__":
    server = Server()
    im = Image.open("test_image.jpg")
    newim = im.resize((500,100))
    server.create_new_image(im=im)
    server.perform_modifications(im,newim,json.loads('[{"name":"crop","args":[500,100]}]'))
    metadata = server.get_metadata(newim)
    most_recent_claim = Claim()
    # print(metadata.claims["head"])
    most_recent_claim.create_from_json(json.loads(metadata.claims["head"]))
    print("*"*25)
    print(json.loads(metadata.claims["head"]))
    print(most_recent_claim)
    print(server.verify_metadata(newim,most_recent_claim))
    print(server.get_metadata(im))


