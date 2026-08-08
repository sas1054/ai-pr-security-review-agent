from models import ReviewJob


def test_review_job_from_dict_is_versioned_and_normalized():
    job = ReviewJob.from_dict(
        {
            "event_type": "git.pullrequest.created",
            "organization_url": "https://dev.azure.com/org/",
            "project": "Project",
            "repo_id": "repo",
            "repo_name": "service",
            "pr_id": "7",
            "source_branch": "refs/heads/feature",
            "target_branch": "refs/heads/main",
        }
    )
    assert job.job_version == 1
    assert job.pr_id == 7
    assert job.organization_url == "https://dev.azure.com/org"
    assert job.event_id


def test_review_job_rejects_missing_fields():
    try:
        ReviewJob.from_dict({"pr_id": 1})
    except ValueError as exc:
        assert "event_type" in str(exc)
    else:
        raise AssertionError("missing fields must be rejected")
