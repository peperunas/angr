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

    ################################
    #   PRIVATE METHODS
    ################################

    # TODO: please remove me
    def _hack_state_step(self, simgr, state, original_stash, whitelist=None, last_statement=None):
        tmp_stash_name = "tmp"
        if not simgr.stashes[tmp_stash_name]:
            simgr.stashes[tmp_stash_name] = []

        simgr.stashes[tmp_stash_name].append(state)

        simgr._one_step(stash=tmp_stash_name, whitelist=whitelist, last_stmt=last_statement)

        for state in simgr.stashes[tmp_stash_name]:
            simgr.stashes[original_stash].append(state)

        del(simgr.stashes[tmp_stash_name])


    ################################
    #   PUBLIC METHODS
    ################################

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
        state_whitelist = self._annotated_cfg.get_whitelisted_statements(state.addr)
        state_last_statement = self._annotated_cfg.get_last_statement_index(state.addr)

        l.debug("Stepping state {}".format(state))

        if state_last_statement:
            successors = self.project.factory.successors(state, whitelist=state_whitelist, last_stmt=state_last_statement, **kwargs)
        else:
            successors = self.project.factory.successors(state, whitelist=state_whitelist, **kwargs)

        return {'active': successors.flat_successors,
                'unconstrained': successors.unconstrained_successors,
                'unsat': successors.unsat_successors,
                }

    def step(self, simgr, stash, **kwargs):
        """
        Step this stash of this manager forward. Should call ``simgr._one_step(stash, **kwargs)`` in order to do the
        actual processing.

        Return the stepped manager.
        """
        l.debug("Stepping stash \"{}\"...".format(stash))

        simgr._one_step(stash=stash, **kwargs)

        for state in simgr.stashes[stash]:
            if not state.history.bbl_addrs:
                l.debug("State has not been stepped before.")
                continue
            dst_addr = state.addr
            src_addr = state.history.bbl_addrs[-1]

            l.debug("Checking if we can get to {} from {}...".format(hex(dst_addr), hex(src_addr)))

            if not self._annotated_cfg.should_take_exit(src_addr, dst_addr):
                l.debug("... nope.")
                # moving the state to the cut stash
                simgr.stashes[self.cut_stash_name].append(state)
                simgr.stashes[stash].remove(state)

        return simgr

    def complete(self, simgr):
        """
        Return whether or not this manager has reached a "completed" state, i.e. ``SimulationManager.run()`` should halt.
        """
        return len(simgr.stashes["active"]) == 0