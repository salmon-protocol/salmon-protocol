# Introduction #

The basic idea is to let authors declare a salmon-compatible endpoint for collecting all of the comments and annotations they generate on the Web.  This store would accept everything but likely not re-publish automatically -- instead, it would be a private collection of everything the author has said, in their own storage.

Make it searchable and let users back it up to local storage, and everyone can own their piece of the Web.

# Details #

None yet, just that discovering another endpoint via XRD for a given author is fairly easy.  Just POST Salmon to that endpoint as well.  This doesn't even require warning the user since it's just like putting email in a Sent folder.