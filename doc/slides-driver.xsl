<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

  <xsl:import href="/usr/share/xml/docbook/custom/slides/3.3.1/xsl/xhtml/default.xsl"/>
  <!-- xsl:import href="slides/xsl/default.xsl"/ -->

  <xsl:param name="keyboard.nav">1</xsl:param>
  <xsl:param name="overlay">1</xsl:param>
  <xsl:param name="output.indent">yes</xsl:param>
  <xsl:param name="graphics.dir">graphics</xsl:param>
  <xsl:param name="script.dir">browser</xsl:param>
  <xsl:param name="css.stylesheet.dir">.</xsl:param>
  <xsl:param name="css.stylesheet">slide-style.css</xsl:param>
  <xsl:param name="para.propagates.style">1</xsl:param>

<xsl:template match="foil">
  <xsl:param name="thisfoil">
    <xsl:apply-templates select="." mode="filename"/>
  </xsl:param>

  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="home" select="/slides"/>
  <xsl:variable name="up"   select="(parent::slides|parent::foilgroup)[1]"/>
  <xsl:variable name="next" select="(following::foil
                                    |following::foilgroup)[1]"/>
  <!-- xsl:variable name="prev" select="(preceding-sibling::foil[1]
                                    |parent::foilgroup[1]
                                    |/slides)[last()]"/ -->
  <!-- xsl:variable name="prev" select="(preceding::foil|preceding::foilgroup|preceding::slides)[1]"/ -->
  <xsl:variable name="prev" select="(preceding::foil|preceding::foilgroup)[last()]"/>
  <!-- xsl:if test="$prev = ''">
    <xsl:variable name="prev" select="parent"/>
  </xsl:if -->

  <xsl:call-template name="write.chunk">
    <xsl:with-param name="indent" select="$output.indent"/>
    <xsl:with-param name="filename" select="concat($base.dir, $thisfoil)"/>
    <xsl:with-param name="content">
      <html>
        <head>
          <title><xsl:value-of select="title"/></title>

          <!-- Links -->

          <link type="text/css" rel="stylesheet">
            <xsl:attribute name="href">
              <xsl:call-template name="css.stylesheet"/>
            </xsl:attribute>
          </link>

          <xsl:call-template name="links">
            <xsl:with-param name="home" select="$home"/>
            <xsl:with-param name="up" select="$up"/>
            <xsl:with-param name="next" select="$next"/>
            <xsl:with-param name="prev" select="$prev"/>
          </xsl:call-template>

          <!-- Scripts -->

          <xsl:if test="$overlay != 0 or $keyboard.nav != 0">
            <script language="JavaScript1.2" type="text/javascript"/>
          </xsl:if>

          <xsl:if test="$keyboard.nav != 0">
            <xsl:call-template name="ua.js"/>
            <xsl:call-template name="xbDOM.js">
              <xsl:with-param name="language" select="'JavaScript'"/>
            </xsl:call-template>
            <xsl:call-template name="xbStyle.js"/>
            <xsl:call-template name="xbCollapsibleLists.js"/>
            <xsl:call-template name="slides.js">
              <xsl:with-param name="language" select="'JavaScript'"/>
            </xsl:call-template>
          </xsl:if>

          <xsl:if test="$overlay != '0'">
            <xsl:call-template name="overlay.js">
              <xsl:with-param name="language" select="'JavaScript'"/>
            </xsl:call-template>
          </xsl:if>
        </head>
        <body class="foil">
          <xsl:call-template name="body.attributes"/>
          <xsl:if test="$overlay != 0">
            <xsl:attribute name="onload">
              <xsl:text>overlaySetup('lc')</xsl:text>
            </xsl:attribute>
          </xsl:if>
          <xsl:if test="$keyboard.nav != 0">
            <xsl:attribute name="onkeypress">
              <xsl:text>navigate(event)</xsl:text>
            </xsl:attribute>
          </xsl:if>

          <div class="{name(.)}">
            <a name="{$id}"/>
            <xsl:call-template name="foil-top-nav">
              <xsl:with-param name="home" select="$home"/>
              <xsl:with-param name="up" select="$up"/>
              <xsl:with-param name="next" select="$next"/>
              <xsl:with-param name="prev" select="$prev"/>
            </xsl:call-template>

            <div class="foil-body">
              <xsl:call-template name="foil-body">
                <xsl:with-param name="home" select="$home"/>
                <xsl:with-param name="up" select="$up"/>
                <xsl:with-param name="next" select="$next"/>
                <xsl:with-param name="prev" select="$prev"/>
              </xsl:call-template>
            </div>

            <div id="overlayDiv">
              <xsl:call-template name="overlayDiv.attributes"/>
              <xsl:call-template name="foil-bottom-nav">
                <xsl:with-param name="home" select="$home"/>
                <xsl:with-param name="up" select="$up"/>
                <xsl:with-param name="next" select="$next"/>
                <xsl:with-param name="prev" select="$prev"/>
              </xsl:call-template>
            </div>
          </div>

          <xsl:call-template name="process.footnotes"/>
        </body>
      </html>
    </xsl:with-param>
  </xsl:call-template>
</xsl:template>


<xsl:template match="foilgroup">
  <xsl:param name="thisfoilgroup">
    <xsl:apply-templates select="." mode="filename"/>
  </xsl:param>

  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="home" select="/slides"/>
  <xsl:variable name="up" select="(parent::slides|parent::foilgroup)[1]"/>
  <xsl:variable name="next" select="foil[1]"/>
  <!-- xsl:variable name="prev" select="(preceding::foil|parent::foilgroup|/slides)[last()]"/ -->
  <xsl:variable name="prev" select="(preceding::foil|preceding::foilgroup)[last()]"/>

  <xsl:call-template name="write.chunk">
    <xsl:with-param name="indent" select="$output.indent"/>
    <xsl:with-param name="filename" select="concat($base.dir, $thisfoilgroup)"/>
    <xsl:with-param name="content">
      <html>
        <head>
          <title><xsl:value-of select="title"/></title>

          <!-- Links -->

          <link type="text/css" rel="stylesheet">
            <xsl:attribute name="href">
              <xsl:call-template name="css.stylesheet"/>
            </xsl:attribute>
          </link>

          <xsl:call-template name="links">
            <xsl:with-param name="home" select="$home"/>
            <xsl:with-param name="up" select="$up"/>
            <xsl:with-param name="next" select="$next"/>
            <xsl:with-param name="prev" select="$prev"/>
          </xsl:call-template>

          <!-- Scripts -->

          <xsl:if test="$overlay != 0 or $keyboard.nav != 0">
            <script language="JavaScript1.2" type="text/javascript"/>
          </xsl:if>

          <xsl:if test="$keyboard.nav != 0">
            <xsl:call-template name="ua.js"/>
            <xsl:call-template name="xbDOM.js">
              <xsl:with-param name="language" select="'JavaScript'"/>
            </xsl:call-template>
            <xsl:call-template name="xbStyle.js"/>
            <xsl:call-template name="xbCollapsibleLists.js"/>
            <xsl:call-template name="slides.js">
              <xsl:with-param name="language" select="'JavaScript'"/>
            </xsl:call-template>
          </xsl:if>

          <xsl:if test="$overlay != '0'">
            <xsl:call-template name="overlay.js">
              <xsl:with-param name="language" select="'JavaScript'"/>
            </xsl:call-template>
          </xsl:if>
        </head>
        <body class="foilgroup">
          <xsl:call-template name="body.attributes"/>
          <xsl:if test="$overlay != 0">
            <xsl:attribute name="onload">
              <xsl:text>overlaySetup('lc')</xsl:text>
            </xsl:attribute>
          </xsl:if>
          <xsl:if test="$keyboard.nav != 0">
            <xsl:attribute name="onkeypress">
              <xsl:text>navigate(event)</xsl:text>
            </xsl:attribute>
          </xsl:if>

          <div class="{name(.)}">
            <a name="{$id}"/>
            <xsl:call-template name="foilgroup-top-nav">
              <xsl:with-param name="home" select="$home"/>
              <xsl:with-param name="up" select="$up"/>
              <xsl:with-param name="next" select="$next"/>
              <xsl:with-param name="prev" select="$prev"/>
            </xsl:call-template>

            <div class="foilgroup-body">
              <xsl:call-template name="foilgroup-body">
                <xsl:with-param name="home" select="$home"/>
                <xsl:with-param name="up" select="$up"/>
                <xsl:with-param name="next" select="$next"/>
                <xsl:with-param name="prev" select="$prev"/>
              </xsl:call-template>
            </div>

            <div id="overlayDiv">
              <xsl:call-template name="overlayDiv.attributes"/>
              <xsl:call-template name="foilgroup-bottom-nav">
                <xsl:with-param name="home" select="$home"/>
                <xsl:with-param name="up" select="$up"/>
                <xsl:with-param name="next" select="$next"/>
                <xsl:with-param name="prev" select="$prev"/>
              </xsl:call-template>
            </div>
          </div>

          <xsl:call-template name="process.footnotes"/>
        </body>
      </html>
    </xsl:with-param>
  </xsl:call-template>

  <xsl:apply-templates select="foil"/>
</xsl:template>


<!--
Local Variables:
mode: xml
coding: utf-8
-->

</xsl:stylesheet>
