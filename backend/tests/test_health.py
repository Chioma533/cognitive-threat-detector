import unittest

from app import create_app


class HealthEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app().test_client()

    def test_health_returns_api_status(self) -> None:
        response = self.client.get("/api/v1/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})
        self.assertTrue(response.is_json)


if __name__ == "__main__":
    unittest.main()
