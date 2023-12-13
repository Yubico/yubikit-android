const core = require('@actions/core')
const { getOctokit, context } = require('@actions/github')
const glob = require('@actions/glob')
const { XMLParser } = require('fast-xml-parser')
const { readFileSync } = require('fs')

async function getAnnotations() {
  const parseOptions = {
    ignoreAttributes: false,
  }

  const pattern =
    core.getInput('WORKSPACE_ROOT') + '**/build/reports/spotbugs/*.xml'

  const globber = await glob.create(pattern)

  annotations = []

  for await (const reportFile of globber.globGenerator()) {
    const parser = new XMLParser(parseOptions)
    let data = parser.parse(readFileSync(reportFile))

    if (Array.isArray(data.BugCollection.BugInstance)) {
      console.log(
        `File: ${data.BugCollection.Project['@_projectName']} Bugs: ${data.BugCollection.BugInstance.length} `,
      )

      for (const bugInstance of data.BugCollection.BugInstance) {
        if (
          Object.hasOwn(bugInstance, 'Method') &&
          !Array.isArray(bugInstance.Method)
        ) {
          annotations.push({
            path: bugInstance.Method.SourceLine['@_sourcepath'],
            start_line: Number(bugInstance.Method.SourceLine['@_start']),
            end_line: Number(bugInstance.Method.SourceLine['@_end']),
            annotation_level: 'warning',
            title: bugInstance.ShortMessage,
            message: bugInstance.LongMessage,
          })
        }
      }
    }
  }

  return annotations
}

async function getCheckRunId(params) {
  const listForRef = await params.octokit.rest.checks.listForRef({
    ...context.repo,
    ref: context.ref,
  })

  const check_run = listForRef.data.check_runs.find(
    (check_run) => check_run.name === params.name,
  )

  if (!check_run) {
    // create new check
    const check = await params.octokit.rest.checks.create({
      ...context.repo,
      name: params.name,
      head_sha: context.sha,
      status: 'completed',
      conclusion: 'success',
      output: {
        title: 'SpotBugs report',
        summary: 'Discovered issues',
      },
    })
    return check.data.id
  } else {
    return check_run.id
  }
}

async function updateCheckRun(params) {
  await params.octokit.rest.checks.update({
    ...context.repo,
    check_run_id: params.check_run_id,
    status: 'completed',
    conclusion: 'success',
    output: {
      title: 'SpotBugs report',
      summary: 'Discovered issues',
      annotations: params.annotations,
    },
  })
}

async function publishCheckRun(annotations) {
  const maxAnnotationsPerCall = 50
  const checkRunName = 'SpotBugs'

  const token = core.getInput('token')
  const octokit = getOctokit(token)

  const checkRunId = await getCheckRunId({
    octokit: octokit,
    name: checkRunName,
  })

  console.log(`Check id: ${checkRunId}`)

  for (
    let index = 0;
    index < annotations.length;
    index += maxAnnotationsPerCall
  ) {
    console.log(`index: ${index}`)
    const chunk = annotations.slice(index, index + maxAnnotationsPerCall)
    console.log(`Annotations: ${JSON.stringify(chunk)}`)
    await updateCheckRun({
      octokit: octokit,
      check_run_id: checkRunId,
      annotations: chunk,
    })
  }
}

async function run() {
  try {
    const annotations = await getAnnotations()
    await publishCheckRun(annotations)
  } catch (error) {
    core.setFailed(error.message)
  }
}

run()
