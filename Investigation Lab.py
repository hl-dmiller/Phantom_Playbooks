"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'domain_reputation_1' block
    domain_reputation_1(container=container)

    # call 'file_reputation_1' block
    file_reputation_1(container=container)

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

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_high_positives, name="geolocate_ip_1")

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

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=join_high_positives, name="domain_reputation_1")

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

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=join_high_positives, name="file_reputation_1")

    return

def high_positives(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('high_positives() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", ">", 100],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_high_positives(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_high_positives() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['file_reputation_1', 'domain_reputation_1', 'geolocate_ip_1']):
        
        # call connected block "high_positives"
        high_positives(container=container, handle=handle)
    
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="Notify_IT", parameters=parameters, response_types=response_types, callback=prompt_timeout)

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
            ["Notify_IT:action_result.status", "==", "\"success\""],
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
            ["Notify_IT:action_result.summary.responses.0", "==", "\"Yes\""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
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