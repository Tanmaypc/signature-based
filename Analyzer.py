from multiprocessing import Process, Event, Queue

from scapy.layers.l2 import Ether

from signature import Signature
from importer import RULES


class Analyzer(Process):
    """Analyze network packets for intrusions."""

    def __init__(self, task_queue, output_file):
        """
        Initialize the Analyzer process.

        Args:
            task_queue (Queue): Queue for receiving packets to analyze.
            output_file (file): File to write intrusion logs.
        """
        super().__init__()
        self.daemon = True
        self.stop_event = Event()
        self.task_queue = task_queue
        self.output_file = output_file

    def is_intrusion(self, packet, packet_index):
        """
        Check if a packet matches any intrusion rule.

        Args:
            packet (Ether): Ethernet packet to analyze.
            packet_index (int): Index of the packet.

        Returns:
            bool: True if intrusion detected, False otherwise.
        """
        packet_summary = packet.summary()
        try:
            packet_signature = Signature(packet)
        except ValueError as err:
            print(f"Error: {err} - Packet summary: {packet_summary}")
            return False

        for rule in RULES:
            if packet_signature == rule:
                intrusion_msg = f"Intrusion detected: {rule} ~> {packet_summary}"
                print(f"[!!] {intrusion_msg}")
                self.output_file.write(f"{intrusion_msg}\n")
                self.output_file.flush()
                return True
        print(f"[=] No intrusion detected - Packet summary: {packet_summary}")
        return False

    def run(self):
        """
        Start the Analyzer process.

        Continuously retrieves packets from the task queue and analyzes them for intrusions.
        """
        packet_index = 1
        while not self.stop_event.is_set():
            packet = self.task_queue.get()
            if packet is None:
                break  # Exit loop when receiving a None signal
            self.is_intrusion(Ether(packet), packet_index)
            packet_index += 1

    def stop(self):
        """Stop the Analyzer process."""
        self.stop_event.set()
        self.task_queue.put(None)  # Signal to exit the loop in run()


def main():
    # Create a task queue and output file
    task_queue = Queue()
    output_file = open("intrusion_log.txt", "a")

    # Start the analyzer process
    analyzer = Analyzer(task_queue, output_file)
    analyzer.start()

    # Simulate packet processing (replace this with your packet source)
    for packet_data in YOUR_PACKET_SOURCE:
        task_queue.put(packet_data)

    # Stop the analyzer process after packet processing
    analyzer.stop()
    analyzer.join()

    # Close the output file
    output_file.close()


if __name__ == "__main__":
    main()