from dartguard import DecisionGuard, Authorization

# Demonstration only: use a real independent policy service.
def trusted_policy(context):
    return Authorization(permitted=context['permission_from_policy_service'],
                         fresh=context['metadata_fresh'])

guard = DecisionGuard(model=lambda state: state['probability'],
                      authorization=trusted_policy)
print(guard.predict({'probability': .93},
                    {'permission_from_policy_service': False, 'metadata_fresh': True}))
