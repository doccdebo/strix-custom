"""Unit tests for Docker sandbox image pull behavior."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from strix.runtime.docker_client import StrixDockerSandboxClient


class TestStrixDockerSandboxClient(unittest.IsolatedAsyncioTestCase):
    async def test_skips_pull_when_image_already_exists(self) -> None:
        client = object.__new__(StrixDockerSandboxClient)
        client.docker_client = MagicMock()
        client.docker_client.containers.create.return_value = MagicMock(short_id="abc123")
        client.image_exists = MagicMock(return_value=True)

        with self.assertLogs("strix.runtime.docker_client", level="INFO") as logs:
            await client._create_container("ghcr.io/usestrix/strix-sandbox:1.0.0")

        client.docker_client.images.pull.assert_not_called()
        create_kwargs = client.docker_client.containers.create.call_args.kwargs
        self.assertEqual(create_kwargs["image"], "ghcr.io/usestrix/strix-sandbox:1.0.0")
        self.assertEqual(create_kwargs["extra_hosts"]["host.docker.internal"], "host-gateway")
        self.assertIn("already present locally, skipping pull", "\n".join(logs.output))

    async def test_pulls_when_image_is_missing(self) -> None:
        client = object.__new__(StrixDockerSandboxClient)
        client.docker_client = MagicMock()
        client.docker_client.containers.create.return_value = MagicMock(short_id="abc123")
        client.image_exists = MagicMock(side_effect=[False, True])

        with self.assertLogs("strix.runtime.docker_client", level="INFO") as logs:
            await client._create_container("ghcr.io/usestrix/strix-sandbox:1.0.0")

        client.docker_client.images.pull.assert_called_once_with(
            "ghcr.io/usestrix/strix-sandbox",
            tag="1.0.0",
            all_tags=False,
        )
        self.assertIn("not found locally, pulling now", "\n".join(logs.output))
        self.assertIn("pulled successfully", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
