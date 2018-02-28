from . import ExplorationTechnique
import logging

"""
An otiegnqwvk is a set of hooks for a simulation manager that assists in the implementation of new techniques in
symbolic exploration.

TODO: choose actual name for the functionality (techniques? strategies?)

Any number of these methods may be overridden by a subclass.
To use an exploration technique, call ``simgr.use_technique`` with an *instance* of the technique.
"""
l = logging.getLogger("angr.exploration_techniques.slicecutor")

class Slicecutor(ExplorationTechnique):
    def __init__(self, annotated_cfg, start=None, force_taking_exit=False, cut_stash_name="cut"):
        """
        :param annotated_cfg: the annotated cfg, used to determine what to execute
        :param start: a path (or set of paths) to start the analysis from
        :param force_taking_exit:
        :param cut_stash_name: the stash where will be placed cut states
        """
        super(Slicecutor, self).__init__()

        self._start = start
        self._annotated_cfg = annotated_cfg
        self._force_taking_exit = force_taking_exit

        # this is the stash containing the states that we cut due to the slicing
        self.cut_stash_name = cut_stash_name

    def setup(self, simgr):
        """
        Perform any initialization on this manager you might need to do.
        """
        if self.cut_stash_name not in simgr.stashes:
            simgr.stashes[self.cut_stash_name] = []


    def step_state(self, state, **kwargs):
        """
        Perform the process of stepping a state forward.

        If the stepping fails, return None to fall back to a default stepping procedure.
        Otherwise, return a dict of stashes to merge into the simulation manager. All the states
        will be added to the SimManager's stashes based on the mapping in the returned dict.
        """
        return None


    def step(self, simgr, stash, **kwargs):
        """
        Step this stash of this manager forward. Should call ``simgr._one_step(stash, **kwargs)`` in order to do the
        actual processing.

        Return the stepped manager.
        """
        l.debug("Stepping {}...".format(stash))


        #whitelist = state._whitelist, last_stmt = state._last_stmt
        simgr = simgr._one_step(stash=stash, **kwargs)

        for state in simgr.stashes[stash]:
            dst_addr = state.addr
            src_addr = state.history.bbl_addrs[-1]

            l.debug("Checking if we can get to {} from {}...".format(hex(dst_addr), hex(src_addr)))

            if not self._annotated_cfg.should_take_exit(src_addr, dst_addr):
                l.debug("... nope.")
                # moving the state to the cut stash
                simgr.stashes[self.cut_stash_name].append(state)
                simgr.stashes[stash].remove(state)

        return simgr


    def filter(self, state):
        """
        Perform filtering on a state.

        If the state should not be filtered, return None.
        If the state should be filtered, return the name of the stash to move the state to.
        If you want to modify the state before filtering it, return a tuple of the stash to move the state to and the
        modified state.
        """
        l.debug("Checking path {} for filtering...".format(state))
        # TODO: fix AnnotatedCFG.filter_state()
        # if self._annotated_cfg.filter_state(state):
        #     l.debug("... {} is cut by AnnoCFG explicitly.".format(state))
        #     return self.cut_stash_name
        return None


    def complete(self, simgr):
        """
        Return whether or not this manager has reached a "completed" state, i.e. ``SimulationManager.run()`` should halt.
        """
        return len(simgr.stashes["active"]) == 0