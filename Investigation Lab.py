"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_4' block
    decision_4(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_Filter_Banned_Countries, name="geolocate_ip_1")

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=join_Filter_Banned_Countries, name="domain_reputation_1")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=join_Filter_Banned_Countries, name="file_reputation_1")

    return

def high_positives(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('high_positives() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", ">", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Notify_IT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Notify_IT() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """A potentially malicious file download has been detected on a local server with IP
address {0}. Notify IT team?"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    #responses:
    response_types = [
        {
            "prompt": "Notify IT?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
        {
            "prompt": "Briefly describe reason for decision.",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Notify_IT", parameters=parameters, response_types=response_types, callback=prompt_timeout)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Notify_IT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def prompt_timeout(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_timeout() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Notify_IT:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        event_promote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    pin_add_comment_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def event_promote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('event_promote() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Notify_IT:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_artifact_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_status_add_comment_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Compose_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Compose_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Compose_comment() called')
    
    template = """Virus positives {0} are below threshold 10, closing event."""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.data.*.positives",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Compose_comment")

    Below_risk_threshold_close(container=container)

    return

def Below_risk_threshold_close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Below_risk_threshold_close() called')

    formatted_data_1 = phantom.get_format_data(name='Compose_comment')

    phantom.set_status(container=container, status="Closed")

    phantom.comment(container=container, comment=formatted_data_1)

    return

def pin_add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_add_comment_3() called')

    phantom.pin(container=container, data="", message="Awaiting Action", pin_type="card", pin_style="red", name=None)

    phantom.comment(container=container, comment="User failed to promote event within time limit.")

    return

def set_status_add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_add_comment_4() called')

    results_data_1 = phantom.collect2(container=container, datapath=['Notify_IT:action_result.summary.responses.1'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.set_status(container=container, status="Closed")

    phantom.comment(container=container, comment=results_item_1_0)

    return

def Promote_to_Case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Promote_to_Case() called')
    
    # call playbook "Phantom_Playbooks/Case Promotion Lab", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="Phantom_Playbooks/Case Promotion Lab", container=container, name="Promote_to_Case")

    return

def add_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_artifact_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_artifact_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['Notify_IT:action_result.summary.responses.1', 'Notify_IT:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_artifact_1' call
    for results_item_1 in results_data_1:
        parameters.append({
            'name': "Promote Reason",
            'label': "event",
            'cef_name': "reason",
            'contains': "",
            'cef_value': results_item_1[0],
            'container_id': "",
            'cef_dictionary': "",
            'run_automation': "true",
            'source_data_identifier': "Investigation lab",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom'], callback=Promote_to_Case, name="add_artifact_1")

    return

def Filter_Banned_Countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_Banned_Countries() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "in", "custom_list:Banned Countries"],
        ],
        name="Filter_Banned_Countries:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_name", "not in", "custom_list:Banned Countries"],
        ],
        name="Filter_Banned_Countries:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def join_Filter_Banned_Countries(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Filter_Banned_Countries() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['geolocate_ip_1', 'domain_reputation_1', 'file_reputation_1']):
        
        # call connected block "Filter_Banned_Countries"
        Filter_Banned_Countries(container=container, handle=handle)
    
    return

def pin_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_5() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_Banned_Countries:condition_1:geolocate_ip_1:action_result.data.*.country_name'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.pin(container=container, data="", message=filtered_results_item_1_0, pin_type="card", pin_style="red", name=None)
    high_positives(container=container)

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_2() called')
    
    template = """Origin country {0} is low risk, closing event."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Filter_Banned_Countries:condition_2:geolocate_ip_1:action_result.data.*.country_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    Low_Risk_Country(container=container)

    return

def Low_Risk_Country(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Low_Risk_Country() called')

    formatted_data_1 = phantom.get_format_data(name='format_2')

    phantom.set_status(container=container, status="Closed")

    phantom.comment(container=container, comment=formatted_data_1)

    return

def playbook_Phantom_Playbooks_Phantom_Playbooks_Log_File_Hashes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_Phantom_Playbooks_Phantom_Playbooks_Log_File_Hashes_1() called')
    
    # call playbook "Phantom_Playbooks/Log File Hashes", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="Phantom_Playbooks/Log File Hashes", container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.source_data_identifier", "!=", "Investigation Lab"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        geolocate_ip_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        playbook_Phantom_Playbooks_Phantom_Playbooks_Log_File_Hashes_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return