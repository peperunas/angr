import angr
from IPython import embed
import logging

logger = logging.getLogger("angr.exploration_techniques.slicecutor")
logger.setLevel(logging.DEBUG)
f = "/home/giulio/gitstuff/angr-doc/examples/fauxware/fauxware"

#####################################################################

p = angr.Project(f, load_options={"auto_load_libs":False})
state = p.factory.entry_state()
simgr = p.factory.simgr(state)

cfg = p.analyses.CFGAccurate(keep_state=True)
ddg = p.analyses.DDG(cfg)
cdg = p.analyses.CDG(cfg)

target_node = cfg.get_any_node(0x400570)

bs = p.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

annocfg = bs.annotated_cfg()
sl = angr.exploration_techniques.Slicecutor(annotated_cfg=annocfg)
simgr.use_technique(sl)

embed()
