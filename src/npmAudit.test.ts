import { createStubSourcegraphAPI } from '@sourcegraph/extension-api-stubs'
import mock from 'mock-require'
const sourcegraph = createStubSourcegraphAPI()
mock('sourcegraph', sourcegraph)

import { getClosestPackageJSON, } from './npmAudit'
import * as assert from 'assert'

describe('npm audit', () => {
    describe('getClosestPackageJSON()', () => {
        it('works when TODO', () => {
            assert.strictEqual(getClosestPackageJSON('', []), 'TODO')
        })
    })

    // packageToAuditBody()

    // auditResponseToMarkdown()
})
