from langgraph.graph import MessagesState


class ValidationState(MessagesState):
    """
    State container for the SEPSES Cyber-KG Validation Agent.
    Inherits MessagesState to support rich logging and historical instructions.
    """
    # Daftar berkas Turtle .ttl yang dijadwalkan untuk divalidasi
    validation_plan: list[dict]
    
    # Berkas .ttl yang sedang aktif divalidasi oleh Executor
    current_task: dict
    
    # Kumpulan hasil evaluasi rinci dari tugas-tugas yang telah diproses
    validation_results: list[dict]
    
    # Flag penunjuk bahwa seluruh rencana pengujian telah dituntaskan
    all_done: bool
