const core = require('@actions/core')
const { getOctokit, context } = require('@actions/github')
const glob = require('@actions/glob')
const { XMLParser } = require('fast-xml-parser')
const { readFileSync } = require('fs')

function bugAnnotation(bug) {
  if (Object.hasOwn(bug, 'Method') && !Array.isArray(bug.Method)) {
    console.log(`Processing ${JSON.stringify(bug, null, 4)}`)
    const title = `${bug.ShortMessage} (${bug['@_category']})`
    const message = `${bug.LongMessage}\n\nSummary:\n...`
    const rawDetails = bug.LongMessage
    const path = bug.Method.SourceLine.hasOwnProperty('@_relSourcePath')
      ? bug.Method.SourceLine['@_relSourcepath']
      : bug.Method.SourceLine['@_sourcepath']
    return {
      title: title,
      message: message,
      raw_details: rawDetails,
      path: path,
      start_line: Number(bug.Method.SourceLine['@_start']),
      end_line: Number(bug.Method.SourceLine['@_end']),
      annotation_level: 'warning',
    }
  }
  return null
}

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
        const annotation = bugAnnotation(bugInstance)
        if (annotation != null) {
          annotations.push(annotation)
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
    for (let annotation of annotations) {
      console.log(`Annotation: ${JSON.stringify(annotation, null, 4)}`)
    }
    // await publishCheckRun(annotations)
  } catch (error) {
    core.setFailed(error.message)
  }
}

run()
