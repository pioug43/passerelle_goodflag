from django.contrib import admin

from .models import (
    GoodflagDocumentTrace,
    GoodflagWebhookEvent,
    GoodflagWorkflowTrace,
)


@admin.register(GoodflagWorkflowTrace)
class GoodflagWorkflowTraceAdmin(admin.ModelAdmin):
    list_display = (
        'goodflag_workflow_id',
        'external_ref',
        'workflow_name',
        'status',
        'resource',
        'created_at',
        'updated_at',
    )
    list_filter = ('status', 'resource')
    search_fields = (
        'goodflag_workflow_id',
        'external_ref',
        'workflow_name',
    )
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'


@admin.register(GoodflagWebhookEvent)
class GoodflagWebhookEventAdmin(admin.ModelAdmin):
    list_display = (
        'event_id',
        'event_type',
        'goodflag_workflow_id',
        'raw_status',
        'normalized_status',
        'resource',
        'received_at',
    )
    list_filter = ('event_type', 'normalized_status', 'resource')
    search_fields = (
        'event_id',
        'goodflag_workflow_id',
        'event_type',
    )
    readonly_fields = ('received_at',)
    ordering = ('-received_at',)
    date_hierarchy = 'received_at'


@admin.register(GoodflagDocumentTrace)
class GoodflagDocumentTraceAdmin(admin.ModelAdmin):
    list_display = (
        'goodflag_document_id',
        'goodflag_workflow_id',
        'filename',
        'content_type',
        'document_type',
        'file_size',
        'resource',
        'uploaded_at',
    )
    list_filter = ('content_type', 'document_type', 'resource')
    search_fields = (
        'goodflag_document_id',
        'goodflag_workflow_id',
        'filename',
    )
    readonly_fields = ('uploaded_at',)
    ordering = ('-uploaded_at',)
    date_hierarchy = 'uploaded_at'
