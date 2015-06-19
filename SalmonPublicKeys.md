NOTE: Most of this has been obsoleted by Magic Signatures.  Some of the key rotation mechanisms detailed here are not yet in the MS spec so I'm leaving this page as a historical document/source of input to the specification for now.

#summary A PKI proposal for Salmon

# Introduction #

PROPOSAL:  For full generality, Salmon needs a Public Key Infrastructure, so this invents a lightweight one based on XRD and Webfinger.

# Details #

Just publish public keys from any XRD, which lets us map any URI (including Webfinger acct:joe@example.org URIs) to a public key for that user:

```
<XRD>
...
<Link>
  <Rel>http://salmon-protocol.org/publickey</Rel>
  <URI>data:application/salmon-publickey,s=blah,e=bleh,k=AHEIJ3334...</URI>
</Link>
</XRD>

where salmon-pkey is a URL-parameter-encoded string, with parameters
s=Earliest timestamp that key is valid for (required)
e=Oldtest timestamp that key is valid for (optional)
k=bytes of public key, in base64 encoded form.
```

Then there's the question of how to deal with key rotation and key revocation.  I propose that these be handled with the same format, different rel value:

```
<Link>
  <Rel>http://salmon-protocol.org/historical-publickey</Rel>
  <URI>data:application/salmon-publickey,s=0,e=5,k=AHEIJ3334...</URI>
</Link>
<Link>
  <Rel>http://salmon-protocol.org/historical-publickey</Rel>
  <URI>data:application/salmon-publickey,s=6,e=20,k=AHEIJ3334...</URI>
</Link>
```

If we also need to explicitly represent compromised/revoked keys we can have a rel value for that too.

With the above, Salmon sources only need to look for Rel="publickey" and sanity check timestamp, because if someone loses their public key in the time it takes the salmon to swim upstream something is very wrong indeed.

Anyone who wants to double check history may need to look in the historical-public list of keys to see if historical salmon were valid or not valid.

In all cases, the claimed timestamp for the salmon should be checked against the public key lifeline and the constraint s <= updated <= max(e,infinity) has to be true for the signature to be valid.