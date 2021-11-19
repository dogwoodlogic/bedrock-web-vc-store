/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
export default class VerifiableCredentialStore {
  /**
   * Each instance of this API is associated with a single edvClient and
   * performs initialization (ensures required indexes are created)
   * 
   * @param {object} options - The options to use.
   * @param {object} options.edv - An `EdvClient` instance to the remote EDV
   *  that will be used to store credentials.
   * @param {object} options.invocationSigner - An API with an
   *   `id` property and a `sign` function for signing a capability invocation.
   * 
   * @returns {VerifiableCredentialStore} `VerifiableCredentialStore` instance
   */
  constructor({edv, invocationSigner}) {
    this.edvClient = edv;
    this.invocationSigner = invocationSigner;
    this.edvClient.ensureIndex({attribute: [
      'meta.issuer',
      'meta.displayable',
      'content.type'
    ]});
    this.edvClient.ensureIndex({attribute: 'content.id', unique: true});
  }

  /**
   * Gets a verifiable credential by its ID
   *
   * @param {string} id
   */
  async get({id}) {
    const {invocationSigner} = this;
    const {documents: [doc]} = await this.edvClient.find({
      equals: {'content.id': id},
      invocationSigner
    });
    if(!doc) {
      const err = new Error('Verifiable Credential not found.');
      err.name = 'NotFoundError';
      throw err;
    }
    const {content, meta, id} = doc;
    return {
      content,
      meta,
      documentId: id
    };
  }

  /**
   * Gets all verifiable credential instances that match the given parameters
   *
   * @param {object|Array} query
   *
   * @return {Promise<Array>} List of matching VCs
   */
  async find({query} = {}) {
    if(!query) {
      throw new TypeError('"query" is a required parameter.');
    }
    const equals = [];
    query = Array.isArray(query) ? query : [query];
    for(const {type, issuer, displayable} of query) {
      const entry = {};
      if(type) {
        entry['content.type'] = type;
      }
      if(issuer) {
        entry['meta.issuer'] = issuer;
      }
      if(displayable) {
        entry['meta.displayable'] = displayable;
      }
      equals.push(entry);
    }

    const {invocationSigner} = this;
    const {documents: docs} = await this.edvClient.find({equals, invocationSigner});
    return docs.map(({content, meta, id}) => {
      return {
        content,
        meta,
        documentId: id
      };
    });
  }

  /**
   * Finds the best matching verifiable credential for the given query
   *
   * @param query a VerifiablePresentation credential handler query
   *   (e.g. right now, support `QueryByExample`).
   * @param engine
   *
   * @return {Promise<Array>} List of matching VCs
   */
  async match({query, engine = credentials => credentials}) {
    // needs to be implemented on the edv-client side first
    const {type} = query;
    let results;
    if(type === 'QueryByExample') {
      const {credentialQuery} = query;
      results = await this._queryByExample({credentialQuery});
    } else {
      throw new Error(`Unsupported query type: "${type}"`);
    }
    return results.map(engine);
  }

  /**
   * Stores a verifiable credential in remote private storage
   *
   * @param {object} options - Options to use.
   * @param {object} options.credential - The credential to store.
   * @param {object} options.meta [options.meta={}] - Meta information.
   * @param {object} options.docId [options.docId=undefined] - An optional
   *  document Id that will be used when storing this credential in an edv.
   */
  async insert({credential, meta = {}, docId} = {}) {
    const {invocationSigner} = this;
    meta.issuer = this._getIssuer({credential});
    const doc = await this.edvClient.insert({
      doc: {
        id: docId,
        meta,
        content: credential
      },
      invocationSigner
    });
    return {
      content: doc.content,
      documentId: doc.id
    };
  }

  /**
   * Removes a verifiable credential identified by its ID.
   * 
   * @param {object} options - Options to use.
   * @param {string} options.id - The id of the credential to delete.
   */
  async delete({id}) {
    try {
      const {invocationSigner} = this;
      const {documents: [doc]} = await this.edvClient.find({
        equals: {'content.id': id},
        invocationSigner
      });
      if(!doc) {
        return false;
      }
      return this.edvClient.delete({doc, invocationSigner});
    } catch(e) {
      if(e.response.status === 404) {
        return false;
      }
      throw e;
    }
  }

  async _queryByExample({credentialQuery}) {
    if(!credentialQuery) {
      throw new Error(
        '"credentialQuery" is needed to execute a QueryByExample.');
    }
    if(typeof credentialQuery !== 'object') {
      throw new Error('"credentialQuery" must be an object or an array.');
    }

    // normalize query to be an array
    let query;
    if(Array.isArray(credentialQuery)) {
      query = credentialQuery;
    } else {
      query = [credentialQuery];
    }
    const _query = async ({example, trustedIssuer = []}) => {
      const {type} = example;
      // normalize trusted issuers to be an array
      let trustedIssuers;
      if(Array.isArray(trustedIssuer)) {
        trustedIssuers = trustedIssuer;
      } else {
        trustedIssuers = [trustedIssuer];
      }

      // build query to find all VCs that match any combination of type+issuer
      const query = [];
      const issuers = trustedIssuers.map(({id}) => {
        if(!id) {
          const error = new Error(
            'trustedIssuer without an "id" is unsupported.');
          error.name = 'NotSupportedError';
          throw error;
        }
        return id;
      });
      const types = Array.isArray(type) ? type : [type];

      for(const type of types) {
        if(issuers.length === 0) {
          query.push({type});
          continue;
        }
        for(const issuer of issuers) {
          query.push({type, issuer});
        }
      }
      return this.find({query});
    };
    // // only look for credentials that are required
    // const requiredQuery =  query.filter(({required}) => required);
    // const requiredCredentials = await Promise.all(requiredQuery.map(_query));

    const requiredCredentials = await Promise.all(query.map(_query));
    // flatten results
    const credentials = requiredCredentials
      .reduce((acc, val) => acc.concat(val), []);
    return credentials;
  }

  _getIssuer({credential}) {
    const {issuer} = credential;
    if(!issuer) {
      throw new Error('A verifiable credential MUST have an issuer property');
    }
    if(!(typeof issuer === 'string' || typeof issuer.id === 'string')) {
      throw new Error('The value of the issuer property MUST be either a URI' +
        ' or an object containing an id property.');
    }
    return typeof issuer === 'string' ? issuer : issuer.id;
  }
}
