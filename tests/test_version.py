from policywatch.policies import next_version_number


def test_version_increment_empty():
    assert next_version_number([]) == 1


def test_version_increment_existing():
    assert next_version_number([1, 2, 3]) == 4
