"""The dataset-ingest runtime (ADR-031): processing under the ``nlw_ingest``
role and its Dramatiq entrypoint. Kept apart from ``nlw.ingest`` (the pure,
database- and network-free profiler) and from the worker."""
