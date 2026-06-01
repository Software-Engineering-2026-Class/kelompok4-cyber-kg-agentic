from langgraph.graph import MessagesState


class LinkingState(MessagesState):
    link_plan: list[dict]
    current_task: dict
    linked_results: list[dict]
    all_done: bool
