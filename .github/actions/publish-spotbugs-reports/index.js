const core = require('@actions/core')
const github = require('@actions/github')

try {
  console.log('Publish SpotBugs reports')
} catch (error) {
  core.setFailed(error.message)
}
