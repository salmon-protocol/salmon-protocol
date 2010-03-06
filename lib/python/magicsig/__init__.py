#!/usr/bin/python2.4
#
# Copyright 2009 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Implementation of Magic Signatures protocol.

See Magic Signatures RFC for specification.  This module
implements the Magic Signature API on top of the crypto
layer in magicsigalg.py, hiding the low level crypto details.
"""

__author__ = 'jpanzer@google.com (John Panzer)'


import base64
import xml.dom.minidom as dom

import magicsigalg


def NormalizeUserIdToUri(userid):
  """Normalizes a user-provided user id to a reasonable guess at a URI."""

  userid = userid.strip()

  # If already in a URI form, we're done:
  if (userid.startswith('http:') or
      userid.startswith('https:') or
      userid.startswith('acct:')):
    return userid

  if userid.find('@') > 0:
    return 'acct:'+userid

  # Catchall:  Guess at http: if nothing else works.
  return 'http://'+userid


def _GetSingleElementByTagNameNS(e, ns, tag_name):
  """Small utility to keep me from going insane dealing with minidom."""
  seq = e.getElementsByTagNameNS(unicode(ns), unicode(tag_name))
  assert seq.length > 0
  assert seq.length == 1
  return seq.item(0)


class PublicKeyRetriever(object):
  """Retrieves public key for a signer identifier (URI)."""

  def LookupPublicKey(self, signer_uri):
    # TODO(jpanzer): Really look this up with Webfinger.
    if not signer_uri:
      return None
    return  ('RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
             'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww=='
             '.AQAB'
             '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5'
             'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==')


class MagicEnvelopeProtocol(object):
  """Implementation of Magic Envelope protocol."""

  ENCODING = 'base64url'  # This is a constant for now.
  key_retriever = PublicKeyRetriever()

  def _GetKeypair(self, signer_uri):
    return self.key_retriever.LookupPublicKey(signer_uri)

  def SignMessage(self, text, mimetype, signer_uri):
    """Creates a magic envelope based on input text & current user.

    Input text must be in a recognized format so authorship can be
    verified.

    Args:
      text: Text of message to be signed.
      mimetype: The MIME type of the message to sign.
      signer_uri: The discoverable URI of the signer.
    Returns:
      The Magic Envelope parameters from section 3.1 of the
      Magic Signatures spec, as a dict.
    """

    signer_uri = NormalizeUserIdToUri(signer_uri)

    assert self.CheckAuthorship(text, signer_uri)

    signature_alg = magicsigalg.SignatureAlgRsaSha256(
        self._GetKeypair(signer_uri))
    armored_text = base64.urlsafe_b64encode(
        unicode(text).encode('utf-8')).encode('utf-8')

    return dict (
        data=armored_text,
        encoding=self.ENCODING,
        data_type=mimetype,
        sig=signature_alg.Sign(armored_text),
        alg=signature_alg.GetName(),
    )

  def GetFirstAuthor(self, text):
    """Grabs first author from given message.

    Currently we're assuming most messages are single author
    and punting on what it means to sign a multi-author
    message.  We only look at the first (lexical) author
    in the input and act as if that is the only author.

    Args:
      text: The text of the message.
    Returns:
      The URI of the author of the message.
    """

    d = dom.parseString(text)
    if d.documentElement.tagName == 'entry':
      authors = d.documentElement.getElementsByTagName('author')
      for a in authors:
        uris = a.getElementsByTagName('uri')
        for uri in uris:
          return NormalizeUserIdToUri(uri.firstChild.data)

  def CheckAuthorship(self, text, userid_uri):
    """Checks that userid is identified as an author of the content.

    Note that this does not do a full signature check.

    Args:
      text: The text of the message to check.
      userid_uri: The URI of the author to be checked.
    Returns:
      True iff userid_uri is identified as the first author.
    """

    return self.GetFirstAuthor(text) == userid_uri

  def Verify(self, env):
    """Verifies magic envelope data.

    (Checks that its signature matches the contents).
    Args:
      env: The magic envelope data in dict form (section 3.1 of spec)
    Returns:
      True iff the signature is verified.
    """

    assert env['alg'] == 'RSA-SHA256'
    assert env['encoding'] == self.ENCODING

    # Decode data to text and grab the author:
    text = base64.urlsafe_b64decode(env['data'].encode('utf-8'))
    signer_uri = self.GetFirstAuthor(text)

    verifier = magicsigalg.SignatureAlgRsaSha256(self._GetKeypair(signer_uri))

    return verifier.Verify(env['data'], env['sig'])

  def Parse(self, textinput):
    """Parses a magic envelope.

    Args:
      textinput: Input message in either application/magic-envelope
        or application/atom format.
    Raises:
      ValueError: The input format was unrecognized or badly formed.
    Returns:
      Magic envelope fields in dict format per section 3.1 of spec.
    """

    ns = 'http://salmon-protocol.org/ns/magic-env'

    d = dom.parseString(textinput)
    if d.documentElement.tagName == 'entry':
      env_el = _GetSingleElementByTagNameNS(d, ns, 'provenance')
    elif d.documentElement.tagName == 'me:env':
      env_el = d.documentElement
    else:
      raise ValueError('Unrecognized input format')

    data_el = _GetSingleElementByTagNameNS(env_el, ns, 'data')

    # Pull magic envelope fields out into dict. Don't forget
    # to remove leading and trailing whitepace from each field's
    # data.
    return dict (
        data=data_el.firstChild.data.strip(),
        encoding=data_el.getAttribute('encoding').strip(),
        data_type=data_el.getAttribute('type').strip(),
        alg=_GetSingleElementByTagNameNS(env_el, ns,
                                         'alg').firstChild.data.strip(),
        sig=_GetSingleElementByTagNameNS(env_el, ns,
                                         'sig').firstChild.data.strip(),
    )

  def Unfold(self, env):
    """Unfolds a magic envelope into readable data.

    Args:
       env: The envelope data as a dict per section 3.1 of spec.
    Returns:
       The equivalent Atom entry with an me:provenance element
       containing the original magic signature data.
    """

    d = dom.parseString(base64.urlsafe_b64decode(env['data'].encode('utf-8')))
    assert d.documentElement.tagName == 'entry'

    # Create a provenance and add it in.  Note that support
    # for namespaces on output in minidom is even worse
    # than support for parsing, so we have to specify
    # the qualified name completely here for each element.
    ns = u'http://salmon-protocol.org/ns/magic-env'
    prov = d.createElementNS(ns, 'me:provenance')
    prov.setAttribute('xmlns:me', ns)
    data = d.createElementNS(ns, 'me:data')
    data.appendChild(d.createTextNode(env['data']))
    data.setAttribute('type', 'application/atom+xml')
    data.setAttribute('encoding', env['encoding'])
    prov.appendChild(data)
    alg = d.createElementNS(ns, 'me:alg')
    alg.appendChild(d.createTextNode(env['alg']))
    prov.appendChild(alg)
    sig = d.createElementNS(ns, 'me:sig')
    sig.appendChild(d.createTextNode(env['sig']))
    prov.appendChild(sig)
    d.documentElement.appendChild(prov)

    # Turn it back into text for consumption:
    # Note: toprettyxml screws w/whitespace,
    # use only for debugging really
    #text = d.toprettyxml(encoding='utf-8')
    text = d.toxml(encoding='utf-8')
    d.unlink()
    return text
