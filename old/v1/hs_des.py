import sys
import argparse

import stem
from stem.control import Controller

def main():

    parser = argparse.ArgumentParser(description="%s fetches a Tor hidden "
                                     "service descriptor." % sys.argv[0])

    parser.add_argument("-p", "--port", type=int, default=9050,
                        help="Tor controller port")

    parser.add_argument('onion_address', type=str, help='Onion address')

    args = parser.parse_args()

    with Controller.from_port(port=args.port) as controller:
        controller.authenticate()

        try:
            hs_descriptor = controller.get_hidden_service_descriptor(args.onion_address)
            print(hs_descriptor)

        except stem.DescriptorUnavailable:
            print("Descriptor not found, the hidden service may be offline.")
            return 1


if __name__ == '__main__':
    sys.exit(main())
