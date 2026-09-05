import unittest

from data_pipeline import PacketRecord, build_feature_rows, build_model_windows, packet_from_log


class DataPipelineTests(unittest.TestCase):
    def test_log_mapping_and_features(self):
        events = [
            packet_from_log({"timestamp": 1, "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "proto": "tcp", "dest_port": 80, "bytes": 120, "flags": "SA"}),
            packet_from_log({"timestamp": 2, "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "proto": "tcp", "dest_port": 443, "bytes": 240, "flags": "A"}),
        ]
        rows = build_feature_rows(events, window_seconds=60)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["features"]), 19)
        self.assertEqual(rows[0]["raw_features"]["syn_count"], 1)
        self.assertEqual(rows[0]["raw_features"]["unique_dst_ports"], 2)

    def test_model_windows_are_lstm_shaped(self):
        events = [PacketRecord(float(i * 60), "10.0.0.5", "1.1.1.1", dst_port=443) for i in range(3)]
        rows = build_feature_rows(events, window_seconds=60)
        windows = build_model_windows(rows, sequence_size=2)
        self.assertEqual(len(windows), 2)
        self.assertEqual(len(windows[0]["model_window"]), 2)
        self.assertEqual(len(windows[0]["model_window"][0]), 19)


if __name__ == "__main__":
    unittest.main()
