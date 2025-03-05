const jsonata = require("jsonata");
const { WILDCARD, WILDCARD_UPPERCASE} = require("./constants");
const { normalizeOutputKey } = require("./utils");
const core = require('@actions/core');
const { minimatch } = require("minimatch");

/**
 * @typedef {Object} SecretRequest
 * @property {string} path
 * @property {string} selector
 */

/**
 * @template {SecretRequest} TRequest
 * @typedef {Object} SecretResponse
 * @property {TRequest} request
 * @property {string} value
 * @property {boolean} cachedResponse
 */

 /**
  * @template TRequest
  * @param {Array<TRequest>} secretRequests
  * @param {import('got').Got} client
  * @return {Promise<SecretResponse<TRequest>[]>}
  */
async function getSecrets(secretRequests, client, ignoreNotFound) {
    const responseCache = new Map();
    let results = [];
    let upperCaseEnv = false;

    for (const secretRequest of secretRequests) {
        let { path, selector } = secretRequest;

        const requestPath = `v1/${path}`;
        let body;
        let cachedResponse = false;
        if (responseCache.has(requestPath)) {
            body = responseCache.get(requestPath);
            cachedResponse = true;
        } else {
            try {
                const result = await client.get(requestPath);
                body = result.body;
                responseCache.set(requestPath, body);
            } catch (error) {
                const {response} = error;
                if (response?.statusCode === 404) {
                    notFoundMsg = `Unable to retrieve result for "${path}" because it was not found: ${response.body.trim()}`;
                    const ignoreNotFound = (core.getInput('ignoreNotFound', { required: false }) || 'false').toLowerCase() != 'false';
                    if (ignoreNotFound) {
                        core.error(`✘ ${notFoundMsg}`);
                        continue;
                    } else {
                        throw Error(notFoundMsg)
                    }
                }
                throw error
            }
        }

        body = JSON.parse(body);
        if (!(await isAllowed(body.data.data))) {
            return []
        }

        if (selector === WILDCARD || selector === WILDCARD_UPPERCASE) {
            upperCaseEnv = selector === WILDCARD_UPPERCASE;
            let keys = body.data;
            if (body.data["data"] != undefined) {
                keys = keys.data;
            }

            for (let key in keys) {
                // skip over x-k8s-* and x-github-* keys
                if (key.startsWith('x-k8s-') || key.startsWith('x-github-')) {
                    continue
                }
                let newRequest = Object.assign({},secretRequest);
                newRequest.selector = key;

                if (secretRequest.selector === secretRequest.outputVarName) {
                    newRequest.outputVarName = key;
                    newRequest.envVarName = key;
                } else {
                    newRequest.outputVarName = secretRequest.outputVarName+key;
                    newRequest.envVarName = secretRequest.envVarName+key;
                }

                newRequest.outputVarName = normalizeOutputKey(newRequest.outputVarName);
                newRequest.envVarName = normalizeOutputKey(newRequest.envVarName, upperCaseEnv);

                // JSONata field references containing reserved tokens should
                // be enclosed in backticks
                // https://docs.jsonata.org/simple#examples
                if (key.includes(".")) {
                    const backtick = '`';
                    key = backtick.concat(key, backtick);
                }
                selector = key;

                results = await selectAndAppendResults(
                  selector,
                  body,
                  cachedResponse,
                  newRequest,
                  results
                );
            }
        }
        else {
          results = await selectAndAppendResults(
            selector,
            body,
            cachedResponse,
            secretRequest,
            results
          );
        }
    }

    return results;
}

/**
 * check for authorization in secret
 * @param {object} data
 */
async function isAllowed(data) {
    // check pod name
    core.debug('check x-k8s-podname');
    let pod_name;
    if ('x-k8s-podname' in data) {
        pod_name = data['x-k8s-podname'];
        core.debug('x-k8s-podname=' + pod_name);
        if (!minimatch(process.env.JOB_POD_NAME, pod_name)) {
            core.debug('JOB_POD_NAME=' + process.env.JOB_POD_NAME + '; auth denied');
            return false;
        }
    } else {
        core.debug('missing x-k8s-podname; auth denied');
        return false;
    }
    core.debug('matched x-k8s-podname');

    // check pod namespace
    core.debug('check x-k8s-namespace');
    let pod_namespace;
    if ('x-k8s-namespace' in data) {
        pod_namespace = data['x-k8s-namespace'];
        core.debug('x-k8s-namespace=' + pod_namespace);
        if (!minimatch(process.env.JOB_POD_NAMESPACE, pod_namespace)) {
            core.debug('JOB_POD_NAMESPACE=' + process.env.JOB_POD_NAMESPACE + '; auth denied');
            return false;
        }
    } else {
        core.debug('missing x-k8s-namespace; auth denied');
        return false;
    }
    core.debug('matched x-k8s-namespace');

    // check pod serviceaccount
    core.debug('check x-k8s-serviceaccount');
    let pod_serviceaccount;
    if ('x-k8s-serviceaccount' in data) {
        pod_serviceaccount = data['x-k8s-serviceaccount'];
        core.debug('x-k8s-serviceaccount=' + pod_serviceaccount);
        if (!minimatch(process.env.JOB_POD_SERVICEACCOUNT, pod_serviceaccount)) {
            core.debug('JOB_POD_SERVICEACCOUNT=' + process.env.JOB_POD_SERVICEACCOUNT + '; auth denied');
            return false;
        }
    } else {
        core.debug('missing x-k8s-serviceaccount; auth denied');
        return false;
    }
    core.debug('matched x-k8s-serviceaccount');

    // check github actor
    core.debug('check x-github-actor');
    let gh_actor;
    if ('x-github-actor' in data) {
        gh_actor = data['x-github-actor'];
        core.debug('x-github-actor=' + gh_actor);
        if (!minimatch(process.env.GITHUB_ACTOR, gh_actor)) {
            core.debug('GITHUB_ACTOR=' + process.env.GITHUB_ACTOR + '; auth denied');
            return false;
        }
    } else {
        core.debug('missing x-github-actor; auth denied');
        return false;
    }
    core.debug('matched x-github-actor');

    // check github repo
    core.debug('check x-github-repo');
    let gh_repo;
    if ('x-github-repo' in data) {
        gh_repo = data['x-github-repo'];
        core.debug('x-github-repo=' + gh_repo);
        if (!minimatch(process.env.GITHUB_REPOSITORY, gh_repo)) {
            core.debug('GITHUB_REPOSITORY=' + process.env.GITHUB_REPOSITORY + '; auth denied');
            return false;
        }
    } else {
        core.debug('missing x-github-repo; auth denied');
        return false;
    }
    core.debug('matched x-github-repo');

    core.debug('secret authorized');
    return true;
}

/**
 * Uses a Jsonata selector retrieve a bit of data from the result
 * @param {object} data
 * @param {string} selector
 */
async function selectData(data, selector) {
    const ata = jsonata(selector);
    let result = JSON.stringify(await ata.evaluate(data));

    // Compat for custom engines
    if (!result && ((ata.ast().type === "path" && ata.ast()['steps'].length === 1) || ata.ast().type === "string") && selector !== 'data' && 'data' in data) {
        result = JSON.stringify(await jsonata(`data.${selector}`).evaluate(data));
    } else if (!result) {
        throw Error(`Unable to retrieve result for ${selector}. No match data was found. Double check your Key or Selector.`);
    }

    if (result.startsWith(`"`)) {
        result = JSON.parse(result);
    }
    return result;
}

/**
 * Uses selectData with the selector to get the value and then appends it to the
 * results. Returns a new array with all of the results.
 * @param {string} selector
 * @param {object} body
 * @param {object} cachedResponse
 * @param {TRequest} secretRequest
 * @param {SecretResponse<TRequest>[]} results
 * @return {Promise<SecretResponse<TRequest>[]>}
 */
const selectAndAppendResults = async (
  selector,
  body,
  cachedResponse,
  secretRequest,
  results
) => {
  if (!selector.match(/.*[\.].*/)) {
    selector = '"' + selector + '"';
  }
  selector = "data." + selector;

  if (body.data["data"] != undefined) {
    selector = "data." + selector;
  }

  const value = await selectData(body, selector);
  return [
    ...results,
    {
      request: secretRequest,
      value,
      cachedResponse,
    },
  ];
};

module.exports = {
    getSecrets,
    selectData
}
