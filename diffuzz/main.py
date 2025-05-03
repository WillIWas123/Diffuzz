from diffuzz.options import Options
from diffuzz.scan_types import Sniper, DualSniper, BatteringRam, DualBatteringRam, PitchFork, DualPitchFork, ClusterBomb, DualClusterBomb
from httpinsert.insertion_points import find_insertion_points

def main():
    options = Options()
    insertion_points = find_insertion_points(options.req,default=True,location="Manual")
    if len(insertion_points) == 0:
        if options.args.scan_path:
            insertion_points.extend(find_insertion_points(options.req,default=True,location="Path"))
        if options.args.scan_query:
            insertion_points.extend(find_insertion_points(options.req,default=True,location="Query"))
        if options.args.scan_headers:
            insertion_points.extend(find_insertion_points(options.req,default=True,location="Headers"))
        if options.args.scan_body:
            insertion_points.extend(find_insertion_points(options.req,default=True,location="Body"))
        if not options.args.scan_path and not options.args.scan_query and not options.args.scan_headers and not options.args.scan_body:
            insertion_points.extend(find_insertion_points(options.req,default=True))
    if len(insertion_points) == 0:
        options.logger.warn("No insertion points found!")
        return

    if options.args.scan_type.lower() == "sniper":
        fuzzer = Sniper(options)
    elif options.args.scan_type.lower() == "dualsniper":
        fuzzer = DualSniper(options)
    elif options.args.scan_type.lower() == "pitchfork":
        fuzzer = PitchFork(options)
    elif options.args.scan_type.lower() == "dualpitchfork":
        fuzzer = DualPitchFork(options)
    elif options.args.scan_type.lower() == "clusterbomb":
        fuzzer = ClusterBomb(options)
    elif options.args.scan_type.lower() == "dualclusterbomb":
        fuzzer = DualClusterBomb(options)
    elif options.args.scan_type.lower() == "batteringram":
        fuzzer = BatteringRam(options)
    elif options.args.scan_type.lower() == "dualbatteringram":
        fuzzer = DualBatteringRam(options)
    else:
        raise NotImplementedError(f"Scan type '{options.args.scan_type}' is not implemented")
    fuzzer.scan(insertion_points)


if __name__ == "__main__":
    main()

