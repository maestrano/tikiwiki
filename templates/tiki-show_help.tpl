{* $Id: tiki-show_help.tpl 46076 2013-05-29 09:19:08Z jonnybradley $ *}
<div class="help" id="tikihelp">
	<div class="help_sections" id="help_sections" style="display:none">
		<ul>
			{foreach item=help from=$help_sections}
				<li>
					<a href="#{$help.id}">
						{$help.title}
					</a>
				</li>
			{/foreach}
		</ul>
		{foreach item=help from=$help_sections}
			<div id="{$help.id}" class="">
				{$help.content}
			</div>
		{/foreach}
	</div>
</div>
<br>
